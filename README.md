# Simple-Inline-Hooking

Using VEH to handle hooking because it takes only 1 byte

problems: its slow as heck!
solutions: i can practically hook every syscall(except it doesnt work for some syscalls????? yea windows is weird 😔)and not hog the memory space with a bunch of tramoplines :D

-> maybe try using Dr7 registers to breakpoint within `mov r10, rcx` and `syscall`

credits: @avale
