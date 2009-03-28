/*
 * Copyright (c) 2009 Chris Smith
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.md87.util.crypto;

import java.util.Arrays;

/**
 * Implements the ARC4 algorithm.
 *
 * @author chris
 */
public class ArcFourEncrypter {

    /** The key to use for encryption. */
    final String key;

    /** The output of the key scheduling algorithm. */
    final byte[] ostate = new byte[256];

    /**
     * Creates a new encrypter that will use the specified key.
     *
     * @param key The key to use for encrypting
     */
    public ArcFourEncrypter(final String key) {
        this.key = key;

        byte[] bytes = key.getBytes();

        for (int i = 0; i < 256; i++) {
            ostate[i] = (byte) i;
        }

        int keyindex = 0;
        int stateindex = 0;

        for (int i = 0; i < 256; i++) {
            final byte t = ostate[i];
            stateindex = (stateindex + bytes[keyindex] + t) & 0xff;
            final byte u = ostate[stateindex];
            ostate[stateindex] = (byte) (t & 0xff);
            ostate[i] = (byte) (u & 0xff);

            keyindex = (keyindex + 1) % bytes.length;
        }
    }

    /**
     * Encrypts the specified bytes.
     *
     * @param bytes The bytes to be encrypted
     * @return The encrypted bytes
     */
    public byte[] encrypt(final byte[] bytes) {
        final byte[] state = Arrays.copyOf(ostate, ostate.length);
        final byte[] dest = new byte[bytes.length];
        int x = 0, y = 0;
        
        for (int i = 0; i < bytes.length; i++) {
            byte sx, sy;

            x = (x + 1) & 0xff;
            sx = state[x];
            y = (sx + y) & 0xff;
            sy = state[y];

            state[y] = (byte) (sx & 0xff);
            state[x] = (byte) (sy & 0xff);

            dest[i] = (byte) (((int) bytes[i] ^ state[(sx + sy) & 0xff]) & 0xff);
        }

        return dest;
    }
    
}
