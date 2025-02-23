# bofArgue
The "new" folder contains a copy with removed comments and debug printstatements... However, without the comments and printstatements in the current file, it puts a bunch of random garbage characters on the end of the strings, for both the fake arguments and the real arguments. I have not figured out what is causing it, so I just have two copies for now.

# Background
Most of the work was done by _xpn_. I adapted it with parameter inputs and turned it into a BOF.

# What does it do?
The BOF does 3 main things. It run's a process with a set of arguments in a suspended state, then it replaces the command line with the real/next set of arguments, and then it will modify the buffer length in the PEB to a set value to "hide" the real arguments.
More details about this process can be found on _xpn_'s blog post linked here: https://blog.xpnsec.com/how-to-argue-like-cobalt-strike/

# How to use it?
The BOF is expecting 3 or 4 parameters. It functionally ignores all parameters after 4. The parameters are 3 strings and an int.
   1. The first string is the Fully binary path to the executable you run.
   2. The second string is the Fake Arguments that it will start the executable with.
   3. The third string is the Real Arguments that you actually want it to run with.
   4. The fourth argument is an int. This int, is the number charcters you want the buffer to show. It defaults to the binpath of the executable if you dont specify. If you put '-1' it will clear the buffer length, to "hide" the whole command line.
