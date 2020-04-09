
This repository contains software for the Micron Storage Engine, also
known as the Night Fury Storage Engine.  Throughout the code and
documentation you'll see the abbreviations "MSE" and "NF".  The MSE name
is preferred as it is slightly more official.

The primary Night Fury git repo can be
[browsed here](https://stash.micron.com/stash/projects/SBUSW/repos/nf/browse),
and the SBU Software team's collection of git repos (including Night Fury)
can be [browsed here](https://stash.micron.com/stash/projects/SBUSW).

# How to get the source code

In order to clone, you need access to the main Night Fury git repository
on Stash.  Once you have that, do this:

    git clone https://YOURMICRONID@stash.micron.com/stash/scm/sbusw/nf.git

However, this access method will require you to enter a password every time
you or the build touches the git server.  To avoid that, you need to load
your ssh public key into Stash; then you can clone this way, which does not
require your password to be interactively entered:

    git clone ssh://git@stash.micron.com:7999/sbusw/nf.git

# How to build the software

To build for the first time:

    make config
    make debug
    make release

To do a full rebuild (also works for first time builds):

    make rebuild

To run unit tests

    make test # NOTE: only runs tests on debug builds

To learn more Makefile tricks:

    make help

# Build prerequisites

TBD.  We need to start from a vanilla Linux install and keep track
of packages tha are required to build the software...

# Workflow

We branch from a project integration branch called "nfpib".  You should make
feature/bugfix branches from the tip of nfpib and, following review and test,
push them to Stash as follows:

    git push origin mybranch:ready/mybranch

Jenkins will then build and test and, if it succeeds, will then merge your
change into nfpib.

# Documentation

* [Git Repo Strategy](Documentation/Repos.md)
* [Source Tree Layout](Documentation/SourceLayout.md)
* [Markdown Example](Documentation/Markdown.md)

