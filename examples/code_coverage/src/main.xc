// Copyright 2016-2022 XMOS LIMITED.
// This Software is subject to the terms of the XMOS Public Licence: Version 1.
#include <platform.h>
#include <print.h>
#include <xs1.h>
#include <stdio.h>
#include <stdint.h>

void test_chan_1 ( chanend c, int x ) {
    c <: 5;
}

void test_chan_2 ( chanend c ) {
    for (int i=0; i<10; i++){
        select {
            case c :> int x :
                break ;
        }
    }
}

void test_for_loop(chanend c){
    for(int i = 0; i<10; i++){
        test_chan_1(c,i);
    }
}

interface my_interface {
    void fA ( int x , int y ) ;
    void fB ( float x ) ;
};

void test_interface_1 ( client interface my_interface i ){
// 'i ' is the client end of the connection ,
// let ' s communicate with the other end .
    i . fA (5 , 10) ;
    // i . fB (10.2);
}

void test_interface_2 ( server interface my_interface i )
{
// wait for either fA or fB over connection 'i '.
    select {
        case i . fA ( int x , int y ) :
            x = x + y ;
            break ;
        case i . fB ( float x ) :
            x += 2.22;
            break ;
    }
}

void rx_chan(chanend d){
    select{              
        case d :> int s: 
            break;       
    }
}

void dummy_fn(chanend d){
    d <: 10;
}

void simple_chan_tx(int t, chanend d){
    if (t == 1){
        d <: t;
    }
    else if (t == 2){
        dummy_fn(d);
    }
}


int main()
{
    interface my_interface i ;
    chan c, d;

    par{
        on tile[0]: test_interface_1(i);
        on tile[0]: test_interface_2(i);
        on tile[0]: simple_chan_tx(1, d);
        on tile[1]: rx_chan(d);
        on tile[1]: test_for_loop(c);
        on tile[1]: test_chan_2(c);
    }
    return 0;
}
