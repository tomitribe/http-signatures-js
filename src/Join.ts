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

import { StringBuilder } from "ts-tomitribe-util";
import { Collection } from "./Collection";

export class Join {
    public static join(delimiter : string, ...collection : (Collection|string)[]) : string {
        if(collection.length === 0) {
            return "";
        } else if(collection[0] instanceof Array) {
            collection = collection[0] as Collection;
        }
        let sb:StringBuilder = new StringBuilder();

        for(let obj of collection) {
            sb.append(obj).append(delimiter);
        }
        return sb.toString().substring(0, sb.length - delimiter.length);
    }
}
