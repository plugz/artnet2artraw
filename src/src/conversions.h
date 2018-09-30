#ifndef __CONVERSIONS_HPP__
#define __CONVERSIONS_HPP__

#include <stdint.h>

// target is 5 bytes long
// cb is 4 bytes long, 8bit value
// cr is 4 bytes long, 8bit value
static inline void conv_cbcr_to_5bit(uint8_t* target, uint8_t const* cb, uint8_t const* cr)
{
    target[0] = (((cb[0] >> 3) & 0x1f) << 3)
        | (((cr[0] >> 3) & 0x1f) >> 2);

    target[1] = (((cr[0] >> 3) & 0x1f) << 6)
        | (((cb[1] >> 3) & 0x1f) << 1)
        | (((cr[1] >> 3) & 0x1f) >> 4);

    target[2] = (((cr[1] >> 3) & 0x1f) << 4) 
        | (((cb[2] >> 3) & 0x1f) >> 1);

    target[3] = (((cb[2] >> 3) & 0x1f) << 7) 
        | (((cr[2] >> 3) & 0x1f) << 2) 
        | (((cb[3] >> 3) & 0x1f) >> 3);

    target[4] = (((cb[3] >> 3) & 0x1f) << 5) 
        | ((cr[3] >> 3) & 0x1f);
}

// target is 5 bytes long
// cb is 4 bytes long, 8bit value
// cr is 4 bytes long, 8bit value
static inline void conv_cbcr_from_5bit(uint8_t const* source, uint8_t* cb, uint8_t* cr)
{
    cb[0] = ((source[0] >> 3) & 0x1f) << 3;
    cr[0] = (((source[0] << 2) & 0x1c) | ((source[1] >> 6) & 0x03)) << 3;
    cb[1] = ((source[1] >> 1) & 0x1f) << 3;
    cr[1] = (((source[1] << 4) & 0x10) | ((source[2] >> 4) & 0x0f)) << 3;
    cb[2] = (((source[2] << 1) & 0x1e) | ((source[3] >> 7) & 0x01)) << 3;
    cr[2] = ((source[3] >> 2) & 0x1f) << 3;
    cb[3] = (((source[3] << 3) & 0x18) | ((source[4] >> 5) & 0x07)) << 3;
    cr[3] = ((source[4]) & 0x1f) << 3;
}

static inline void conv_ycbcr_from_rgb(uint8_t const* rgb, uint8_t* y, uint8_t* cb, uint8_t* cr)
{
    float r = rgb[0];
    float g = rgb[1];
    float b = rgb[2];

    float yf = 0 + (0.299f * r) + (0.587f * g) + (0.114f * b);
    float cbf = 128 - (0.168736f * r) - (0.331264f * g) + (0.5f * b);
    float crf = 128 + (0.5f * r) - (0.418688 * g) - (0.081312f * b);

    *y = yf;
    *cb = cbf;
    *cr = crf;
}

static inline void conv_ycbcr_to_rgb(uint8_t* rgb, uint8_t y, uint8_t cb, uint8_t cr)
{
    float yf = y;
    float cbf = cb;
    float crf = cr;

    float r = yf + 1.402f * (crf - 128);
    float g = yf - 0.344136f * (cbf - 128) - 0.714136 * (crf - 128);
    float b = yf + 1.772f * (cbf - 128);

    if (r < 0)
        r = 0;
    else if (r > 255)
        r = 255;

    if (g < 0)
        g = 0;
    else if (g > 255)
        g = 255;

    if (b < 0)
        b = 0;
    else if (b > 255)
        b = 255;

    rgb[0] = r;
    rgb[1] = g;
    rgb[2] = b;
}

#endif
