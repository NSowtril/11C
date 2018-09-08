/*************************************************
 *                  animation.h                  *
 *                                               *
 *              Chudi LAN, September, 2018       *
 *************************************************/

#ifndef __OWLS_ANIMATION_H__
#define __OWLS_ANIMATION_H__

#define BLACK               0x70
#define BLUE                0x71
#define GREEN               0x72
#define BLUE_GREEN          0x73
#define ORANGE              0x76
#define WHITE               0x77
#define GRAY                0x78
#define BLUE_LIGHT          0x79
#define GREEN_LIGHT         0x7A
#define BLUE_GREEN_LIGHT    0x7B
#define YELLOW              0x7E
#define WHITE_LIGHT         0x7F

/*======================================================================*
                            The boot animation
 *======================================================================*/
void p0(int n, int color){
    for(int i = 0; i < n; i++){

        disp_color_str("0",color);
    }
}

void animation(){

    int c0=0x70;int c2=0x72;int c3 = 0x73;int c6=0x76;int c7 = 0x77;int c8 = 0x78;int cb=0x7B; int ce=0x7E; int cf=0x7F;
    clear();
    milli_delay(1000); 
    p0(55,c7);p0(14,c8);p0(11,c7);
    milli_delay(1000);
    p0(53,c7);p0(2,c8);p0(14,c3);p0(2,c8);p0(9,c7);
    milli_delay(1000);
    p0(48,c7);p0(2,c8);p0(3,c8);p0(16,c3);p0(2,c8);p0(1,c8);p0(8,c7);
    milli_delay(1000);
    p0(38,c7);p0(1,c8);p0(2,c3);p0(1,c8);p0(5,c7);p0(3,c8);p0(20,c3);p0(1,c8);p0(9,c7);
    milli_delay(1000);
    p0(11,c7);p0(12,c8);p0(14,c7);p0(1,c8);p0(3,c3);p0(1,c8);p0(3,c7);p0(2,c8);p0(23,c3);p0(2,c8);p0(8,c7);  
    milli_delay(1000);
    p0(9,c7);p0(2,c8);p0(11,c3);p0(2,c8);p0(13,c7);p0(1,c8);p0(2,c3);p0(1,c8);p0(3,c7);p0(2,c8);p0(23,c3);p0(2,c8);p0(9,c7);
    milli_delay(1000);
    p0(8,c7);p0(1,c8);p0(16,c3);p0(2,c8);p0(4,c7);p0(1,c8);p0(1,c3);p0(1,c8);p0(3,c7);p0(1,c8);p0(1,c3);p0(1,c8);p0(2,c7);p0(1,c8);p0(19,c3);p0(8,c8);p0(10,c7);
    milli_delay(1000);
    p0(8,c7);p0(1,c8);p0(19,c3);p0(1,c8);p0(2,c7);p0(1,c8);p0(2,c3);p0(1,c8);p0(2,c7);p0(1,c8);p0(3,c7);p0(1,c8);p0(9,c3);p0(2,c8);p0(5,c7);p0(5,c8);p0(17,c7);
    milli_delay(1000);
    p0(9,c7);p0(1,c8);p0(20,c3);p0(1,c8);p0(2,c7);p0(2,c8);p0(5,c7);p0(1,c8); p0(5,c3);p0(2,c8);p0(7,c7);p0(2,c8);p0(7,c3);p0(1,c8);p0(15,c7);
    milli_delay(1000);
    p0(17,c7);p0(9,c8);p0(5,c3);p0(1,c8);p0(7,c7);p0(1,c8);p0(3,c3);p0(2,c8); p0(13,c7);p0(2,c8);p0(4,c3);p0(1,c8);p0(15,c7);
    milli_delay(1000);
    p0(14,c7);p0(1,c8);p0(5,c3);p0(2,c8);p0(6,c7);p0(1,c8);p0(3,c3);p0(1,c8); p0(5,c7);p0(1,c8);p0(2,c3);p0(1,c8);p0(6,c7);p0(7,c8);p0(7,c7);p0(1,c8);p0(17,c7);
    milli_delay(1000);
    p0(13,c7);p0(1,c8);p0(4,c3);p0(1,c8);p0(11,c7);p0(1,c8);p0(2,c3);p0(1,c8); p0(4,c7);p0(1,c8);p0(1,c3);p0(1,c8);p0(5,c7);p0(1,c8);p0(9,cb);p0(2,c8);p0(5,c7);p0(1,c8);p0(3,c3);p0(3,c8);p0(10,c7);
    milli_delay(1000);
    p0(14,c7);p0(3,c8);p0(5,c7);p0(6,c8);p0(4,c7);p0(2,c8);p0(3,c7);p0(1,c8); p0(1,c3);p0(1,c8);p0(4,c7);p0(1,c8);p0(13,cb);p0(1,c8);p0(5,c7);p0(1,c8);p0(5,c3);p0(1,c8);p0(9,c7);
    milli_delay(1000);
    p0(13,c7);p0(3,c8);p0(4,c7);p0(1,c8);p0(8,cb);p0(1,c8);p0(3,c7);p0(1,c8);p0(3,c7);p0(1,c8); p0(1,c3);p0(1,c8);p0(3,c7);p0(1,c8);p0(3,cb);p0(2,c8);p0(3,cb);p0(2,c8);p0(5,cb);p0(1,c8);p0(5,c7);p0(1,c8);p0(5,c3);p0(1,c8);p0(8,c7);
    milli_delay(1000);
    p0(11,c7);p0(2,c8);p0(1,c3);p0(1,c8);p0(3,c7);p0(1,c8);p0(4,cb);p0(5,c8);p0(3,cb);p0(1,c8);p0(5,c7);p0(2,c8); p0(3,c7);p0(1,c8);p0(2,cb);p0(2,c8);p0(4,c0);p0(1,c8);p0(3,cf);p0(1,c8);p0(4,cb);p0(1,c8);p0(4,c7);p0(1,c8);p0(5,c3);p0(1,c8);p0(8,c7);
    milli_delay(1000);
    p0(10,c7);p0(1,c8);p0(3,c3);p0(1,c8);p0(3,c7);p0(3,cb);p0(2,cf);p0(3,c0);p0(3,cf);p0(3,cb);p0(1,c8);p0(9,c7);p0(3,cb); p0(1,cf);p0(1,c8);p0(5,c0);p0(3,c8);p0(1,c0);p0(1,c8);p0(3,cb);p0(1,c8);p0(5,c7);p0(2,c8);p0(3,c3);p0(1,c8);p0(8,c7);
    milli_delay(1000);
    p0(9,c7);p0(1,c8);p0(4,c3);p0(1,c8);p0(2,c7);p0(1,c8);p0(3,cb);p0(1,cf);p0(1,c8);p0(6,c0);p0(1,cf);p0(2,cb);p0(1,c8);p0(9,c7);p0(1,c8);p0(2,cb); p0(2,cf);p0(7,c0);p0(2,cf);p0(1,c8);p0(3,cb);p0(1,c8);p0(4,c7);p0(1,c8);p0(1,c2);p0(5,c8);p0(8,c7);
    milli_delay(1000);
    p0(9,c7);p0(1,c8);p0(4,c3);p0(1,c8);p0(2,c7);p0(1,c8);p0(3,cb);p0(1,c8);p0(1,cf);p0(1,c8);p0(4,c0);p0(1,cf);p0(2,cb);p0(1,c8);p0(10,c7);p0(1,c8);p0(3,cb); p0(2,cf);p0(1,c8);p0(4,c0);p0(2,cf);p0(1,c8);p0(3,cb);p0(1,c8);p0(4,c7);p0(1,c8);p0(3,c2);p0(1,c8);p0(11,c7);
    milli_delay(1000);
    p0(10,c7);p0(1,c8);p0(2,c3);p0(1,c8);p0(1,c2);p0(3,c7);p0(2,c8);p0(3,cb);p0(1,c8);p0(3,cf);p0(1,c8);p0(2,cb);p0(1,c8);p0(2,c7);p0(1,c8);p0(4,c6); p0(1,c8);p0(4,c7);p0(1,c8);p0(4,cb);p0(5,c0);p0(1,c8);p0(4,cb);p0(1,c8);p0(4,c7);p0(1,c8);p0(4,c2);p0(1,c8);p0(11,c7);
    milli_delay(1000);
    p0(13,c7);p0(1,c8);p0(2,c2);p0(1,c8);p0(3,c7);p0(1,c8);p0(7,cb);p0(1,c8);p0(3,c7);p0(1,c8);p0(6,c6);p0(1,c8);p0(4,c7);p0(2,c8);p0(10,cb); p0(2,c8);p0(4,c7);p0(1,c8);p0(5,c2);p0(1,c8);p0(11,c7);
    milli_delay(1000);
    p0(13,c7);p0(1,c8);p0(4,c2);p0(1,c8);p0(13,c7);p0(1,c8);p0(6,c6);p0(1,c8);p0(7,c7);p0(8,c8);p0(7,c7);p0(1,c8);p0(5,c2);p0(1,c8);p0(11,c7);
    milli_delay(1000);
    p0(13,c7);p0(2,c8);p0(4,c2);p0(1,c8);p0(6,c7);p0(1,c8);p0(2,ce);p0(1,c8);p0(2,c7);p0(1,c8);p0(5,c6);p0(1,c8);p0(4,c7);p0(1,c8);p0(1,ce);p0(1,c8);p0(12,c7);p0(1,c8);p0(1,c2);p0(1,c8);p0(1,c7);p0(1,c8);p0(4,c2);p0(1,c8);p0(12,c7);
    milli_delay(1000);
    p0(15,c7);p0(1,c8);p0(4,c2);p0(1,c8);p0(1,c7);p0(1,c8);p0(6,ce);p0(1,c8);p0(3,c7);p0(1,c8);p0(3,c6);p0(1,c8);p0(4,c7);p0(1,c8);p0(7,ce);p0(2,c8);p0(7,c2);p0(1,c8);p0(2,c7);p0(1,c8);p0(3,c2);p0(1,c8);p0(13,c7);
    milli_delay(1000);
    p0(16,c7);p0(5,c8);p0(1,c7);p0(2,c8);p0(5,ce);p0(1,c8);p0(4,c7);p0(1,c8);p0(1,c6);p0(1,c8);p0(4,c7);p0(1,c8);p0(6,ce);p0(3,c8);p0(6,c2);p0(4,c8);p0(18,c7);
    milli_delay(1000);
    p0(24,c7);p0(7,c8);p0(5,c7);p0(1,c8);p0(8,c7);p0(5,c8);p0(2,c7);p0(8,c8);p0(21,c7);
    milli_delay(10000);
    clear_screen(console_table[0].orig,console_table[0].con_size);
}

#endif /*__OWLS_ANIMATION_H__*/