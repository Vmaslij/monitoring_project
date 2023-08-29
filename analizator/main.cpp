#include <cstdio>
#include <iostream>
#include <csignal>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <sys/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <cstring>
#include <cstdlib>
#include "analizator.h"

using namespace std;


int main(int argc, char** argv)
{
    Analizator trafic;
    unsigned char* inter;

    trafic.main_cycle(inter);

    return 0;
}