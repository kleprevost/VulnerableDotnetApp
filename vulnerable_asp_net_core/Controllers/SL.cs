using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using vulnerable_asp_net_core.Models;
using System.Data.SqlClient;
using System.Data.SQLite;
using System.IO;
using System.Net;
using System.Xml;
using System.Xml.Serialization;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.Extensions.Logging;
using vulnerable_asp_net_core.Utils;

namespace vulnerable_asp_net_core.Controllers
{
    public class SL : Controller
    {
        public IActionResult Index()
        {
            var id = HttpContext.Request.Query["id"];
            @ViewData["cookie"] = HttpContext.Request.Cookies["slcookie"];
            @ViewData["result"] = id;
            return View();
        }
        
        public IActionResult SQLInjection()
        {
            string name = Request.Query.ContainsKey("name") ? Request.Query["name"] + "" : "";
            string pw = Request.Query.ContainsKey("pw") ? Request.Query["pw"] + "" : "";
            string res = "";
            
            if (name.Length > 0)
            {
                var command = new SQLiteCommand($"SELECT * FROM users WHERE name = '{name}' and pw = '{pw}'",
                    DatabaseUtils._con);
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        res += reader["name"] + "";
                    }

                }
                @ViewData["result"] = "Successfully logged in as " + res;
            }

            
            if(res.Length == 0)
                @ViewData["result"] = "Please login by providing a valid username and password";
       
            return View();
        }
        
        public IActionResult XXE()
        {
            string xml = Request.Query.ContainsKey("xml") ? Request.Query["xml"] + "" : "";
            
            if (xml.Length <= 0)
            {
                @ViewData["result"] = "upload your request";
            }
            else
            {

                var resolver = new XmlUrlResolver();
                resolver.Credentials = CredentialCache.DefaultCredentials;
                var xmlDoc = new XmlDocument();
                xmlDoc.XmlResolver = resolver;
                
                try
                {
                    xmlDoc.LoadXml(xml);
                }
                catch (Exception){}

                @ViewData["result"] = "Results of your request: " + string.Empty;

                foreach (XmlNode xn in xmlDoc)
                {
                    if (xn.Name == "user") @ViewData["result"] = "Results of your request: " + xn.InnerText;
                }
            }

            return View();
        }
               
        public IActionResult XSS()
        {
            var comment = Request.Query.ContainsKey("comment") ? Request.Query["comment"] + "" : "";
            
            @ViewData["result"] = $"your comment is '{comment}'";
          
            return View();
        }

        private static readonly Dictionary<string, string> Users =
            new Dictionary<string, string> {{"evan", "abc"}, {"marta", "001"}};

        public IActionResult BrokenAuthentication()
        {
            var login = Request.Query.ContainsKey("name") ? Request.Query["name"] + "" : "";
            var pw = Request.Query.ContainsKey("pw") ? Request.Query["pw"] + "" : "";

            if (Users.ContainsKey(login) && Users[login] == pw)
            {
                @ViewData["result"] = "Successfully logged in as " + login;
            }
            else
            {
                @ViewData["result"] = "Please login by providing a valid username and password";;
            }

            return View();
        }
        
        private const string UserPwPlain = @"<data>
									 <user>
									 <name>claire</name>
									 <password>clairepw</password>
									 <account>admin</account>
									 </user>
									 <user>
									 <name>alice</name>
									 <password>alicepw</password>
									 <account>user</account>
									 </user>
									 <user>
									 <name>bob</name>
									 <password>bobpw</password>
									 <account>bob</account>
									 </user>
									 </data>";
        
        public IActionResult XPATHInjection()
        {
            var XmlDoc = new XmlDocument();
            XmlDoc.LoadXml(UserPwPlain);
            var nav = XmlDoc.CreateNavigator();

            var name = Request.Query.ContainsKey("name") ? Request.Query["name"] + "" : "";
            var pw = Request.Query.ContainsKey("pw") ? Request.Query["pw"] + "" : "";

            var query = "string(//user[name/text()='"
                        + name
                        + "' and password/text() ='"
                        + pw + "']/account/text())";

            var expr = nav.Compile(query);
            var account = Convert.ToString(nav.Evaluate(expr));

            if (account.Length <= 0)
            {
                @ViewData["result"] = "Please login by providing a valid username and password";
            }
            else
            {
                @ViewData["result"] = "Successfully logged in as " + account;
            }

            return View();
        }
        
        // credit card security codes are stored encrypted
        private const string UserCreditCardInfo = @"<data>
									 <user>
									 <name>claire</name>
									 <cardno>11111111</cardno>
									 <secno>ba1f2511fc30423bdbb183fe33f3dd0f</secno>
									 </user>
									 <user>
									 <name>alice</name>
									 <cardno>2222222</cardno>
									 <secno>d2d362cdc6579390f1c0617d74a7913d</secno>
									 </user>
									 <user>
									 <name>bob</name>
									 <cardno>33333333</cardno>
									 <secno>aa3f5bb8c988fa9b75a1cdb1dc4d93fc</secno>
									 </user>
									 </data>";

        public IActionResult SensitiveDataExposure()
        {
            var userDoc = new XmlDocument();
            userDoc.LoadXml(UserPwPlain);
            var loginNav = userDoc.CreateNavigator();

            var creditCardDoc = new XmlDocument();
            creditCardDoc.LoadXml(UserCreditCardInfo);
            var creditCardNav = creditCardDoc.CreateNavigator();

            var login = Request.Query.ContainsKey("name") ? Request.Query["name"] + "" : "";
            var pw = Request.Query.ContainsKey("pw") ? Request.Query["pw"] + "" : "";
            var cardprop = Request.Query.ContainsKey("cardprop") ? Request.Query["cardprop"] + "" : "cardno";

            // authenticate user
            var authQuery = "string(//user[name/text()='"
                            + login
                            + "' and password/text() ='"
                            + pw + "']/account/text())";

            var account = Convert.ToString(loginNav.Evaluate(loginNav.Compile(authQuery)));
            if (account.Length <= 0)
            {
                @ViewData["result"] = "Please login by providing a valid username and password";
            }
            else
            {
                var cardno = "string(//user[name/text()='"
                             + login
                             + "']/" + cardprop + "/text())";

                var card = Convert.ToString(creditCardNav.Evaluate(creditCardNav.Compile(cardno)));
                @ViewData["result"] = $"'{login}' successfully logged in; your card-number is '{card}'";
            }

            return View();
        }

        public IActionResult SecurityMisconfiguration()
        {
            var command = new SQLiteCommand("SELECT * FROM user WHERE id = 10", DatabaseUtils._con);
            try
            {
                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        string returnString = string.Empty;
                        returnString += $"Hello {reader["Name"]} ! ";
                        @ViewData["result"] = returnString;
                    }
                    else
                    {
                        @ViewData["result"] = string.Empty;
                    }
                }
            } catch (Exception e){
                @ViewData["result"] = e.Message;
            }
            return View();
        }
        
        public IActionResult BrokenAccessControl()
        {
            var role = Request.Query.ContainsKey("role") && Request.Query["role"].Equals("admin")
                ? "admin"
                : "user";

            string id = Request.Query.ContainsKey("id") && Request.Query["id"].Count > 0 ? Request.Query["id"] + "" : "0";
            
            if (role.Equals("admin"))
            {
                return LocalRedirect("/SL/Admin?id=" + id);
            }

            @ViewData["result"] = $"Logged in as '{role}'";

            return View();
        }
        
        
        public IActionResult Admin()
        {
            string id = Request.Query.ContainsKey("id") && Request.Query["id"].Count > 0 ? Request.Query["id"] + "" : "0";
            //Asynchronous Processing=true;";

            if (id == "0") return View();

            var command = new SQLiteCommand($"DELETE FROM users WHERE id = {Request.Query["id"]}",
                DatabaseUtils._con);

            if (command.ExecuteNonQuery() > 0)
            {
                @ViewData["result"] = $"Deleted user {id}!";
            }
            else
            {
                @ViewData["result"] = string.Empty;
            }

            return View();
        }

        public IActionResult InsecureDeserialization()
        {
            // TODO:
            //https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.binary.binaryformatter?view=netframework-4.7.2
            if (Request.Query.ContainsKey("xml"))
            {
                var xml = Request.Query["xml"];
                var ser_xml = new XmlSerializer(typeof(Executable));
                try
                {
                    var xread = XmlReader.Create(new StringReader(xml));
                    var exe = (Executable) ser_xml.Deserialize(xread);
                    @ViewData["result"] = "Request results: \'" + exe.Run() + "\'";
                }
                catch (Exception)
                {
                    @ViewData["result"] = "Request results: \'\'";
                }
            }

            return View();
        }
           
        public IActionResult InsufficientLogging()
        {

            var log = "";
            string Msg(string msg) {
                return new DateTime() + ":" + msg + "</br>";
            }
            var showlogs = Request.Query.ContainsKey("showlogs");
            if (showlogs)
            {
                log += Msg("[info] user 'alice' logged in");
                log += Msg("[info] user 'claire' logged out");
                log += Msg("[info] user 'bob' logged in");
                log += Msg("[info] user 'bob' logged out");
                log += Msg("[warn] /data is almost full");
            }
            
            @ViewData["result"] = log;
            return View();
        }

        public IActionResult VulnerableComponent()
        {

            var comment = Request.Query.ContainsKey("comment") ? Request.Query["comment"] + "" : "";
            
            @ViewData["result"] = $"your comment is \'" +  Utils.VulnerableComponent.process(comment) + "\'";
          
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel
            {
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
            });
        }
    }
}
