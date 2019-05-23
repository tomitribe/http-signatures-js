import resolve from 'rollup-plugin-node-resolve';
import commonjs from 'rollup-plugin-commonjs';
import sourceMaps from 'rollup-plugin-sourcemaps';
import typescript from 'rollup-plugin-typescript2';
import json from 'rollup-plugin-json';
import { terser } from 'rollup-plugin-terser';
import camelCase from 'lodash.camelcase';

import pkg from './package.json';

const libraryName = pkg.name;
const globals = {'pako': 'pako', 'crypto': 'crypto'};

const baseConfig = {
    input: 'src/index.ts',
    watch: {
        include: 'src/**'
    },
    plugins: [
        json(),
        typescript({useTsconfigDeclarationDir: true}),
        commonjs(),
        resolve({isBrowser: true}),
        sourceMaps()
    ]
};

const es6Config = Object.assign({}, baseConfig, {
    output: {
        file: pkg.es6,
        format: 'es',
        sourcemap: true,
        globals
    },
    external: ['pako', 'crypto'],
    plugins: [
        json(),
        typescript({
            useTsconfigDeclarationDir: true,
            tsconfigOverride: {
                compilerOptions: {
                    target: 'es6',
                    declaration: true
                }
            }
        }),
        commonjs(),
        resolve(),
        sourceMaps()
    ]
});

// separate lib with external `pako` lib as a base
const libConfig = Object.assign({}, baseConfig, {
    external: ['pako', 'crypto'],
    output: [
        {
            file: pkg.module,
            format: 'es',
            sourcemap: true
        },
        {
            file: pkg.main,
            name: camelCase(libraryName),
            format: 'umd',
            sourcemap: true,
            exports: 'named'
        },
        {
            file: pkg.common,
            name: camelCase(libraryName),
            format: 'cjs',
            sourcemap: true,
            exports: 'named'
        }
    ].map(el => ({...el, globals}))
});

const libConfigMin  = Object.assign({}, baseConfig, {
    external: ['pako', 'crypto'],
    output: [].concat(libConfig.output, [es6Config.output]).map(function (item) {
        return Object.assign({}, item, {
            file: item.file.replace(/\.js$/, ".min.js"),
            sourcemap: false,
            globals
        });
    }),
    plugins: [json(), typescript({useTsconfigDeclarationDir: true}), commonjs(), resolve(), terser()]
});

const browserConfig = Object.assign({}, baseConfig, {
    external: ['crypto'],
    output: {
        file: pkg.browser,
        name: camelCase(libraryName),
        format: 'umd',
        exports: 'named',
        sourcemap: false,
        browser: true,
        globals: {'crypto': 'crypto'}
    },
    plugins: [json(), typescript({useTsconfigDeclarationDir: true}), resolve({browser: true}), commonjs(), terser()]
});

const packedConfig = Object.assign({}, baseConfig, {
    external: ['crypto'],
    output: {
        file: pkg.packed,
        name: camelCase(libraryName),
        format: 'iife',
        exports: 'named',
        sourcemap: false,
        globals: {'crypto': 'crypto'}
    },
    plugins: [json(), typescript({useTsconfigDeclarationDir: true}), commonjs(), resolve(), terser()]
});

export default [es6Config, libConfig, libConfigMin, browserConfig, packedConfig];
