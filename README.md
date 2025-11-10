# CdbDap
CdbDap is a wrapper around Microsoft's [cdb cli debugger](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/cdb-command-line-options), implementing the [debug adapter protocol](https://microsoft.github.io/debug-adapter-protocol//).
_CdbDap is in a very early state. You'll likely be as frustrated with it as you were without it._

## Why
At work I have to compile with MSVC.
I use neovim for most of my editing, but currently, there is no good way of debugging MSVC binaries in neovim (see [Alternatives](#alternatives)).
Visual Studio is a major pain with how slow it is, so I was as frustrated as you likely are, if you landed here.
Thus, after finding that the alternatives are very cumbersome and/or insufficient, here we are.

## Continued development
I had the socket code and DAP interaction code generated and didn't really touch it - interaction with Cdb has been working so far.
I had other code for the actual controlling of Cdb generated, but most of it was broken in some form,
so I rewrote large parts of it.
If you think you can do better: Great, that makes two of us! 
Please help out.
Fork the project and improve upon it.
Write a DAP from scratch that doesn't need cdb.
There are plenty of ways the solution could be better than what this is.

I am neither an expert in using cdb, nor in writing DAP servers.
I'm just fumbling my way through this entire ordeal in the hopes of some day not needing to open Visual Studio every day.
I may not ever finish this - don't hold your breath.

## Alterantives
Of course, debugging C++ code on Windows can be done more easily:
* Visual Studio and Visual Studio Code perfectly support MSVC binary debugging. Boy do I hate both of them.
* lldb has some support for debugging MSVC binaries and CodeLLDB is easily integrated. It didn't suffice for the program I'm debugging.
* CLion has good support for MSVC binaries in their lldb version, as far as I can tell. Sadly, it doesn't come with the DAP implementation that the original lldb has, so I cannot use it in my editor.
* You may not need MSVC to compile! If you can use clang, do it and use lldb instead!
* There is a hack to use vsdbg (the VS Code DAP), but that is _very_ cumbersome to setup. This may be your best bet though. In general, the license doesn't allow to use this outside of VS / VSC.

## Usage
If you looked at the alternatives and still want to give this a try, have a look at the [usage](USAGE.md) file.
If you want to use it in neovim, make sure you have all prerequesits (Python, Cdb, ... - see usage) installed and cdb.exe is in your path.
Then add the following to your dap setup:

```
local dap = require('dap')

dap.adapters.cdbdap = {
    type = 'server',
    host = '127.0.0.1',
    port = 13000
}


dap.configurations.cpp = {
    {
        name = "Launch with cdbdap",
        type = "cdbdap",
        request = "launch",
        program = function()
            return vim.fn.input('Path to executable: ', vim.fn.getcwd() .. '/', 'file')
        end,
        cwd = '${workspaceFolder}',
        args = {},
    }
}
```

With everything set up, start `python dap_server.py` and then start a debugging session which connects to the server.

## Issues
As this is an early state, there are lots of issues. Some of them are listed here - so you have been warned.

* Errors not caught correctly - In my program I'm trying this out on, there is a line of code that I haven't been able to get past; still neovim never showed me that the debugger stopped executing. The program didn't crash.
* StopOnEntry - Not supported yet. cdb has a stop on entry functionality, but if you have debugged in lldb or gdb before, you expect this to stop at the beginning of the main function. cdb stops elsewhere, so for now this is "disabled".
* When debugging the test_program.cpp in this repository, multiple threads are started (by Cdb).
This is annoying during debugging, but the "unimportant" threads don't have user code associated, so this should not be a big issue.
* There is support for C style arrays and std::vectors, but not for other containers (yet).
* There is limited support for objects of structs and classes. E.g. in the test_program.cpp You can look into Rectangle, Point and Node - however in the case of Node, the next member will show only an address (that can be expanded though).
