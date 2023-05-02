# d3syscall wp
本题利用内核模块动态修改了系统调用，制作了一个简易的虚拟机。程序首先从`/proc/kallsyms`中获取了系统调用表的地址，通过参数传递到内核模块中，内核模块里注册了`Linux`保留的系统调用，分别为：335：MOV，336：ALU，337：PUSH，338：POP，339：resetreg，340：checkflag。原代码如下（save的时候漏了check）：
```C
int init(void)
{
    sys_call_table_my = (unsigned long *)(magic);
    anything_saved[0] = (int (*)(void))(sys_call_table_my[MOV]);
    anything_saved[1] = (int (*)(void))(sys_call_table_my[ALU]);
    anything_saved[2] = (int (*)(void))(sys_call_table_my[PUSH]);
    anything_saved[3] = (int (*)(void))(sys_call_table_my[POP]);
    anything_saved[4] = (int (*)(void))(sys_call_table_my[RESET]);
    orig_cr0 = clear_cr0();
    sys_call_table_my[MOV] = (unsigned long)&mov;
    sys_call_table_my[ALU] = (unsigned long)&alu;
    sys_call_table_my[PUSH] = (unsigned long)&push;
    sys_call_table_my[POP] = (unsigned long)&pop;
    sys_call_table_my[POP+1] = (unsigned long)&reset;
    sys_call_table_my[POP+2] = (unsigned long)&check;
    setback_cr0(orig_cr0);
    return 0;
}
```
由于本题用`C`语言编写，所以逆向难度并不大。主要的麻烦的地方应该在于如何写反汇编脚本上，因为不同系统调用使用的寄存器数量不同，这里介绍一个比较简单的办法，能够不从汇编代码入手：
使用`Linux`自带的`strace`命令运行本程序，即可`dump`所有的系统调用：
```
syscall_0x14f(0x1, 0, 0x333231, 0xffffffffffffff80, 0, 0x557bacc99890) = 0x333231
syscall_0x14f(0x1, 0x1, 0, 0xffffffffffffff80, 0, 0x557bacc99890) = 0
syscall_0x151(0, 0x1, 0, 0xffffffffffffff80, 0, 0x557bacc99890) = 0x1
syscall_0x14f(0, 0x2, 0, 0xffffffffffffff80, 0, 0x557bacc99890) = 0x333231
syscall_0x14f(0x1, 0x1, 0x3, 0xffffffffffffff80, 0, 0x557bacc99890) = 0x3
syscall_0x150(0x4, 0x2, 0x1, 0xffffffffffffff80, 0, 0x557bacc99890) = 0x1999188
syscall_0x14f(0x1, 0x1, 0x51e7647e, 0xffffffffffffff80, 0, 0x557bacc99890) = 0x51e7647e
...
```
接着稍微整理一下即可拿到比较漂亮的方便处理的数据：
```python
[0x14f,0x1, 0, 0x333231, 0xffffffffffffff80, 0, 0x557bacc99890],
[0x14f,0x1, 0x1, 0, 0xffffffffffffff80, 0, 0x557bacc99890],
[0x151,0, 0x1, 0, 0xffffffffffffff80, 0, 0x557bacc99890],
[0x14f,0, 0x2, 0, 0xffffffffffffff80, 0, 0x557bacc99890],
[0x14f,0x1, 0x1, 0x3, 0xffffffffffffff80, 0, 0x557bacc99890],
[0x150,0x4, 0x2, 0x1, 0xffffffffffffff80, 0, 0x557bacc99890],
[0x14f,0x1, 0x1, 0x51e7647e, 0xffffffffffffff80, 0, 0x557bacc99890],
[0x150,0, 0x2, 0x1, 0xffffffffffffff80, 0, 0x557bacc99890],
[0x14f,0, 0x3, 0, 0xffffffffffffff80, 0, 0x557bacc99890],
```
此时处理起来就比较方便了，我们直接根据逆向结果写反汇编脚本：
```python
bytecode=[[0x14f,0x1, 0, 0x333231, 0xffffffffffffff80, 0, 0x557bacc99890],
[0x14f,0x1, 0x1, 0, 0xffffffffffffff80, 0, 0x557bacc99890],
[0x151,0, 0x1, 0, 0xffffffffffffff80, 0, 0x557bacc99890],
[0x14f,0, 0x2, 0, 0xffffffffffffff80, 0, 0x557bacc99890],
[0x14f,0x1, 0x1, 0x3, 0xffffffffffffff80, 0, 0x557bacc99890],
[0x150,0x4, 0x2, 0x1, 0xffffffffffffff80, 0, 0x557bacc99890],
...
		 ]
def mov(code):
    match code[1]:
        case 0:
            print(f"mov reg[{code[2]}],reg[{code[3]}]")
        case 1:
            print(f"mov reg[{code[2]}],{code[3]}")
def alu(code):
    match code[1]:
        case 0:
            print(f"add reg[{code[2]}],reg[{code[3]}]")
        case 1:
            print(f"sub reg[{code[2]}],reg[{code[3]}]")
        case 2:
            print(f"mul reg[{code[2]}],reg[{code[3]}]")
        case 3:
            print(f"xor reg[{code[2]}],reg[{code[3]}]")
        case 4:
            print(f"shl reg[{code[2]}],reg[{code[3]}]")
        case 5:
            print(f"shr reg[{code[2]}],reg[{code[3]}]")
def push(code):
    match code[1]:
        case 0:
            print(f"push reg[{code[2]}]")
        case 1:
            print(f"push {code[2]}")
def pop(code):
    print(f"pop reg[{code[1]}]")
for i in bytecode:
    match i[0]:
        case 335:
            mov(i)
        case 336:
            alu(i)
        case 337:
            push(i)
        case 338:
            pop(i)
        case 339:
            print("resetreg")
        case 340:
            print("checkflag")
```
加密逻辑如下：
```C
int enc(unsigned long rax,unsigned long rbx)
{
    // printf("%lx %lx ",rax,rbx);
    rbx+=((rax<<3)+0x51e7647e)^(rax*3+0xe0b4140a)^(rax+0xe6978f27);
    rax+=((rbx<<6)+0x53a35337)^(5*rbx+0x9840294d)^(rbx-0x5eae4751);
    printf("0x%lx,0x%lx\n",rax,rbx);
}
```
解密脚本：
```C++
unsigned __int64 flag_enc[] = { 0xb0800699cb89cc89,0x4764fd523fa00b19,0x396a7e6df099d700,0xb115d56bcdeaf50a,0x2521513c985791f4,0xb03c06af93ad0be };

int dec(unsigned __int64 & rax, unsigned __int64 & rbx)
{
    rax -= ((rbx << 6) + 0x53a35337) ^ (5 * rbx + 0x9840294d) ^ (rbx - 0x5eae4751);
    rbx -= ((rax << 3) + 0x51e7647e) ^ (rax * 3 + 0xe0b4140a) ^ (rax + 0xe6978f27);
    printf("%.8s%.8s", &rax,&rbx);
    return 0;
}
int main()
{
    printf("%d\n", sizeof(unsigned long));
    dec(flag_enc[1], flag_enc[0]);
    dec(flag_enc[3], flag_enc[2]);
    dec(flag_enc[5], flag_enc[4]);
}
```
