# About
`SmaliAnalyzer` is a command line tool which can be used to statically analyze Android APK files.

# Build
Build using gradle wrapper:  
> $: cd ~/path/to/SmaliAnalyzer  
> $: ./gradlew build  # build sources 
> $: ./gradlew fatJar # build standalone jar

# Options
 - *-h*: print the help dialog
 - *-f*: specify an APK file or a folder containing APK files. If a folder is specified all contained APK files are parsed.
 - *-o*: specify an folder for generated result files