#include <stdio.h>
#include <string.h>

void hacked()
{
    puts("Hacked by Kevin J!!!");
}

void return_input(void)
{
    char array[301];
    gets(array);
    printf("%s\n", array);
}

main()
{
    return_input();
    return 0;
}