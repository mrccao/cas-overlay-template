# IMPORTANT NOTE<br/>******************************************************<br/>This repository is always automatically generated from the CAS Initializr. Do NOT submit pull requests here as the change-set will be overwritten on the next sync.To learn more, please visit the [CAS documentation](https://apereo.github.io/cas).<br/>******************************************************<br/>
Apereo CAS WAR Overlay Template
=====================================

WAR Overlay Type: `cas-overlay`

# Versions
   

- CAS Server `7.0.0-RC7`
- JDK `17`
                     
# Build

To build the project, use:

```bash
# Use --refresh-dependencies to force-update SNAPSHOT versions
./gradlew[.bat] clean build
```

To see what commands/tasks are available to the build script, run:

```bash
./gradlew[.bat] tasks
```

If you need to, on Linux/Unix systems, you can delete all the existing artifacts
(artifacts and metadata) Gradle has downloaded using:

```bash
# Only do this when absolutely necessary
rm -rf $HOME/.gradle/caches/
```

Same strategy applies to Windows too, provided you switch `$HOME` to its equivalent in the above command.

# Keystore

For the server to run successfully, you might need to create a keystore file.
This can either be done using the JDK's `keytool` utility or via the following command:

```bash
./gradlew[.bat] createKeystore
```

Use the password `changeit` for both the keystore and the key/certificate entries. 
Ensure the keystore is loaded up with keys and certificates of the server.

## Extension Modules

Extension modules may be specified under the `dependencies` block of the [Gradle build script](build.gradle):

```gradle
dependencies {
    implementation "org.apereo.cas:cas-server-some-module"
    ...
}
```

To collect the list of all project modules and dependencies in the overlay:

```bash
./gradlew[.bat] dependencies
```                                                                       

# Deployment

On a successful deployment via the following methods, the server will be available at:


* `https://localhost:8443/cas`


  
## Executable WAR

Run the server web application as an executable WAR. Note that running an executable WAR requires CAS to use an embedded container such as Apache Tomcat, Jetty, etc.

The current servlet container is specified as `-tomcat`.

```bash
java -jar build/libs/cas.war
```

Or via:

```bash
./gradlew[.bat] run
```

Debug the CAS web application as an executable WAR:

```bash
./gradlew[.bat] debug
```
       
Or via:

```bash
java -Xdebug -Xrunjdwp:transport=dt_socket,address=5000,server=y,suspend=y -jar build/libs/cas.war
```

Run the CAS web application as a *standalone* executable WAR:

```bash
./gradlew[.bat] clean executable
```

## External

Deploy the binary web application file in `build/libs` after a successful build to a servlet container of choice.

# Docker

The following strategies outline how to build and deploy CAS Docker images.

## Jib

The overlay embraces the [Jib Gradle Plugin](https://github.com/GoogleContainerTools/jib) to provide easy-to-use out-of-the-box tooling for building CAS docker images. Jib is an open-source Java containerizer from Google that lets Java developers build containers using the tools they know. It is a container image builder that handles all the steps of packaging your application into a container image. It does not require you to write a Dockerfile or have Docker installed, and it is directly integrated into the overlay.

```bash
# Running this task requires that you have Docker installed and running.
./gradlew build jibDockerBuild
```

## Dockerfile

You can also use the Docker tooling and the provided `Dockerfile` to build and run.
There are dedicated Gradle tasks available to build and push Docker images using the supplied `DockerFile`:

```bash
./gradlew build casBuildDockerImage
```

Once ready, you may also push the images:

```bash
./gradlew casPushDockerImage
```

If credentials (username+password) are required for pull and push operations, they may be specified
using system properties via `-DdockerUsername=...` and `-DdockerPassword=...`.

A `docker-compose.yml` is also provided to orchestrate the build:

```bash  
docker-compose build
```

# CAS Command-line Shell

To launch into the CAS command-line shell:

```bash
./gradlew[.bat] downloadShell runShell
```

# Retrieve Overlay Resources

To fetch and overlay a CAS resource or view, use:

```bash
./gradlew[.bat] getResource -PresourceName=[resource-name]
```

# Create User Interface Themes Structure

You can use the overlay to construct the correct directory structure for custom user interface themes:

```bash
./gradlew[.bat] createTheme -Ptheme=redbeard
```

The generated directory structure should match the following:

```
├── redbeard.properties
├── static
│ └── themes
│     └── redbeard
│         ├── css
│         │ └── cas.css
│         └── js
│             └── cas.js
└── templates
    └── redbeard
        └── fragments
```

HTML templates and fragments can be moved into the above directory structure, 
and the theme may be assigned to applications for use.

# List Overlay Resources
 
To list all available CAS views and templates:

```bash
./gradlew[.bat] listTemplateViews
```

To unzip and explode the CAS web application file and the internal resources jar:

```bash
./gradlew[.bat] explodeWar
```

# Configuration

- The `etc` directory contains the configuration files and directories that need to be copied to `/etc/cas/config`.

```bash
./gradlew[.bat] copyCasConfiguration
```

- The specifics of the build are controlled using the `gradle.properties` file.

## Configuration Metadata

Configuration metadata allows you to export collection of CAS properties as a report into a file 
that can later be examined. You will find a full list of CAS settings along with notes, types, default and accepted values:

```bash
./gradlew exportConfigMetadata
```                           

# Puppeteer

> [Puppeteer](https://pptr.dev/) is a Node.js library which provides a high-level API to control Chrome/Chromium over the DevTools Protocol.
> Puppeteer runs in headless mode by default, but can be configured to run in full (non-headless) Chrome/Chromium.

Puppeteer scenarios, used here as a form of acceptance testing, allow you to verify CAS functionality to address a particular authentication flow. The scenarios, which may be
found inside the `./puppeteer/scenarios` directory are designed as small Node.js scripts that spin up a headless browser and walk through a test scenario. You may
design your own test scenarios that verify functionality specific to your CAS deployment or feature.

To execute Puppeteer scenarios, run:

```bash
./puppeteer/run.sh
```

This will first attempt to build your CAS deployment, will install Puppeteer and all other needed libraries. It will then launch the CAS server,
and upon its availability, will iterate through defined scenarios and will execute them one at a time.

The following defaults are assumed:

- CAS will be available at `https://localhost:8443/cas/login`.
- The CAS overlay is prepped with an embedded server container, such as Apache Tomcat.

You may of course need to make adjustments to account for your specific environment and deployment settings, URLs, etc.


# Duct

`duct` is a Gradle task to do quick smoke tests of multi-node CAS high-availability deployments. In particular, it tests correctness of ticket
sharing between multiple individual CAS server nodes backed by distributed ticket registries such as Hazelcast, Redis, etc.

This task requires CAS server nodes to **enable the CAS REST module**. It will **NOT** work without it.

The task accepts the following properties:

- Arbitrary number of CAS server nodes specified via the `duct.cas.X` properties.
- URL of the service application registered with CAS specified via `duct.service`, for which tickets will be requested.
- `duct.username` and `duct.password` to use for authentication, when requesting ticket-granting tickets.

It automates the following scenario:

- Authenticate and issue a service ticket on one CAS node
- Validate this service ticket on the another node
- Repeat (You may cancel and stop the task at any time with `Ctrl+C`)

If the task succeeds, then we effectively have proven that the distributed ticket registry has been set up and deployed
correctly and that there are no connectivity issues between CAS nodes.

To run the task, you may use:

```bash
./gradlew duct
    -Pduct.cas.1=https://node1.example.org/cas \
    -Pduct.cas.2=https://node2.example.org/cas \
    -Pduct.cas.3=https://node3.example.org/cas \
    -Pduct.cas.4=https://node4.example.org/cas \
    -Pduct.service=https://apereo.github.io \
    -Pduct.username=casuser \
    -Pduct.password=Mellon
```

You may also supply the following options:

- `duct.debug`: Boolean flag to output debug and verbose logging.
- `duct.duration`: Number of seconds, i.e. `30` to execute the scenario.
- `duct.count`: Number of iterations, i.e. `5` to execute the scenario.
