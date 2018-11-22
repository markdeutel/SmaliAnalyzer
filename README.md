# About
`SmaliAnalyzer` is a command line tool which can be used to statically analyze Android APK files. When provided with an APK files the tool can automatically search in the file's source code for invocations of getter methods provided by Android's `Intent` class. Based on the gathered information it is possible to derive the structure of the payload of Intents received by different components thoughout the analysed application. To be able to analyse the bytecode stored in the APK files the baksmali library by JesusFreke is used to dissasemble the compield code. Furthermore the `SmaliAnalyzer` tool decompiles the APK's manifest file and parses it for Intent filters. The data colletced this way is usefull to find out about further properties the Intents should have which the exported components of the analyzed application expect to receive.  

# Build
To build the project locally use gradle wrapper:  
```console
$ cd ~/path/to/SmaliAnalyzer  
$ ./gradlew build  # build sources   
$ ./gradlew fatJar # build standalone jar   
``` 

# Options and Configuration
The `SmaliAnalyzer` tool offers a range of command line options:
 - *-h*: print the help dialog
 - *-f*: specify an APK file or a folder containing APK files. If a folder is specified all contained APK files are parsed.
 - *-o*: specify an folder for generated result files

Furthermore the tool can be configured by adjusting its `application.properties` file:
```properties
# path pointing to an installation of Android's aapt tool
tools.android.sdk.aapt.path=/home/mark/Android/Sdk/build-tools/27.0.3/aapt
# path pointing to an installation of the radamsa tool
tools.radamsa.path=radamsa
# maximum recursion depth of the analyzer
constants.max.depth=2
```