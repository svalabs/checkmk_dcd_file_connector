# CSV Import

Import hosts from a CSV file.

## Required adjustment

You have to adjust the local dcd of your site to allow for loading the plugin.
To do so change the file `~/etc/init.d/dcd` the line

```
DAEMON=$OMD_ROOT/bin/dcd
```

to

```
DAEMON=$OMD_ROOT/local/bin/dcd
```


## Building

The project creates a build with every push.
Adjust the version in the `info` file accordingly if you plan to release.