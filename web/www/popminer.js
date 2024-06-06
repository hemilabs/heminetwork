/**
 * Copyright (c) 2024 Hemi Labs, Inc.
 * Use of this source code is governed by the MIT License,
 * which can be found in the LICENSE file.
 */

// Launch go runtime
if (!WebAssembly.instantiateStreaming) { // polyfill
	WebAssembly.instantiateStreaming = async (resp, importObject) => {
		const source = await (await resp).arrayBuffer();
		return await WebAssembly.instantiate(source, importObject);
	};
}

const go = new Go();
let mod, inst;
WebAssembly.instantiateStreaming(fetch("popminer.wasm"), go.importObject).then((result) => {
	mod = result.module;
	inst = result.instance;

	// Always launch go runtime
	go.run(inst);
}).then(() => init()).catch((err) => {
	// XXX restart wasm instead
	console.error(err);
});
