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

import org.junit.Test;
import static org.junit.Assert.*;

public class ArcFourEncrypterTest {

    @Test
    public void testPredefined() {
        assertArrayEquals(new byte[]{(byte) 0x45, (byte) 0xA0, (byte) 0x1F,
                (byte) 0x64, (byte) 0x5F, (byte) 0xC3, (byte) 0x5B,
                (byte) 0x38, (byte) 0x35, (byte) 0x52, (byte) 0x54,
                (byte) 0x4B, (byte) 0x9B, (byte) 0xF5},
                new ArcFourEncrypter("Secret").encrypt("Attack at dawn".getBytes()));
    }

    @Test
    public void testDouble() {
        final ArcFourEncrypter enc = new ArcFourEncrypter("Secret");
        assertEquals("Testing", new String(enc.encrypt(enc.encrypt("Testing".getBytes()))));
    }

}