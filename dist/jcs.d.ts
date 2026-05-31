export type JsonValue = null | boolean | number | string | JsonValue[] | {
    [k: string]: JsonValue | undefined;
};
export declare function canonicalize(value: JsonValue): string;
export declare function canonicalizeBytes(value: JsonValue): Uint8Array;
//# sourceMappingURL=jcs.d.ts.map