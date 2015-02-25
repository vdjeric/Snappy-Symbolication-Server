# RPM spec for Mozilla Snappy Symbolification Server

This will build an RPM suitable for installation on RHEL7'ish.

# Build

* Ensure that `rpmdevtools` and `mock` are available and initialised:
    ```
    $ sudo yum install rpmdevtools mock
    $ rpmdev-setuptree
    ```

* Run `autobuild.sh`:
    ```
    cd ${repo}/
    chmod u+x autobuild.sh
    ./autobuild.sh
    ```

This will pull `master` and build a package whose version corresponds to the
datestamp (in epoch) of the most recent commit.

# More info

See the [source repo](https://github.com/mozilla/Snappy-Symbolication-Server/).
