#!/bin/bash

runme=1
while [ $runme -ne 0 ]
do

    if [[ -n "$JAVA_HOME" ]] && [[ -x "$JAVA_HOME/bin/java" ]];  then
        _java="$JAVA_HOME/bin/java"

    elif type -p java; then
        _java=java

    else
        echo "Java not found - Unable to run"
        runme=0
    fi

    if [[ "$_java" ]]; then
        version=$("$_java" -version 2>&1 | awk -F '"' '/version/ {print $2}')
        if [[ "$version" > "1.79" ]]; then
            echo "Please provide source code path: "
            read path
            echo "Please provide comma separated patterns to be excluded: (Ex: *.java, **/*/*.js)"
            read exclusions
            echo "Do you want to run Library Finder[Yes]? Yes/No"
            read response
            if [ -d "$path" ]; then
                current_time=$(date "+%Y.%m.%d-%H.%M.%S")
                file_name=WHCLOC_$current_time.csv
                "$_java" -jar sast-tools.jar cloc --exclude "$exclusions" --ignore-duplicate-files --directory "$path" --export "$file_name" --print-files
                runme=0
                if [[ $(echo $response |tr [:upper:] [:lower:]) != "no" ]];then 
                    current_time=$(date "+%Y.%m.%d-%H.%M.%S")
                    file_name=WH_LF_$current_time.csv
                    echo ""
                    echo "Library Finder is running."
                    "$_java" -jar sast-tools.jar find-libraries --exclude "$exclusions" --directory "$path" --export "$file_name" 
                    runme=0 
                fi 
            else
                echo "Path does not exist - please provide a valid source code path"
                runme=1
            fi
        else
            echo "Need Java 1.8 - Unable to run"
            runme=0
        fi
    fi
done
