# Check a version with the TypeScript SDK

Start the [local example server](../README.md). From the repository root, build the SDK and install it in the example directory. These commands work before registry publication.

```bash
npm ci --prefix sdk-typescript
npm run build --prefix sdk-typescript
npm install --prefix examples/typescript --no-save --package-lock=false ./sdk-typescript
node sdk-typescript/node_modules/typescript/bin/tsc examples/typescript/demo.mts --module nodenext --target es2022 --skipLibCheck --outDir examples/typescript/dist
node examples/typescript/dist/demo.mjs
```

Expected output:

```text
ALLOW
DENY ANCESTOR_DELETED
```

The same client submits the deletion and observes the new epoch. When a different process revokes a source, decision-cache bounds also apply.
