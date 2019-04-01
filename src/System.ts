/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export class System {
    static arraycopy(srcArr: any[], srcOff: number, destArr: any[], dstOff: number, size: number) {
        if (srcArr !== destArr || dstOff >= srcOff + size) {
            while (--size >= 0) destArr[dstOff++] = srcArr[srcOff++];
        } else {
            let tmp: any[] = srcArr.slice(srcOff, srcOff + size);
            for (let i = 0; i < size; i++) destArr[dstOff++] = tmp[i];
        }
    }
}
