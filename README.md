# CSV Import

Import hosts from a CSV file.

## Required adjustment

This plugin brings its own dcd "binary" that will load the plugin.
You have to adjust the local dcd service of your site to allow for loading the plugin.
To do so change in `~/etc/init.d/dcd` the line

```bash
DAEMON=$OMD_ROOT/bin/dcd
```

to

```bash
DAEMON=$OMD_ROOT/local/bin/dcd
```


## Building

The project creates a build with every push.
Adjust the version in the `info` file accordingly if you plan to release.