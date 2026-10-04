export type ScalarKind = 'int' | 'short' | 'byte' | 'bool' | 'string' | 'enum'

type PrimitiveKind = Exclude<ScalarKind, 'enum'>
type TypeRef = { kind: 'primitive'; primitive: PrimitiveKind; length?: number } | { kind: 'named'; name: string } | { kind: 'array'; element: TypeRef; length: number }
type Definition = { enums: Map<string, string[]>; structs: Map<string, StructDefinition>; root: StructDefinition; sizeBits: number }
type StructDefinition = { fields: FieldDefinition[]; sizeBits: number }
type FieldDefinition = { name: string; type: TypeRef; offsetBits: number }
export type ProfileField = { path: string; kind: ScalarKind; offsetBits: number; value: number | boolean | string; options?: string[]; length?: number }
export type ParsedProfile = { fields: ProfileField[]; checksum: number; checksumValid: boolean; definitionSize: number }

const profileSize = 8192

export function parseDefinition(source: string): Definition {
  const tokens = tokenize(source)
  const enums = new Map<string, string[]>()
  const structs = new Map<string, StructDefinition>()
  const rawStructs = new Map<string, { name: string; type: TypeRef; padding?: number }[]>()
  let root: StructDefinition | undefined
  let index = 0
  const expect = (value: string) => {
    if (tokens[index] !== value) throw new Error(`Expected ${value}, found ${tokens[index] ?? 'end of file'}`)
    index++
  }
  expect('version')
  index++
  expect('{')
  while (tokens[index] !== '}') {
    if (tokens[index] === 'checksumoverride') {
      index += 2
      expect(';')
      continue
    }
    if (tokens[index] === 'enum') {
      index++
      let reservedCount = 0
      if (tokens[index] === '(') {
        index++
        reservedCount = Number(tokens[index++])
        expect(')')
      }
      const name = tokens[index++]
      expect('{')
      const values: string[] = []
      while (tokens[index] !== '}') {
        values.push(JSON.parse(tokens[index++]) as string)
        if (tokens[index] === ',') index++
      }
      expect('}')
      expect(';')
      if (reservedCount > values.length) values.push(...Array(reservedCount - values.length).fill(''))
      enums.set(name, values)
      continue
    }
    if (tokens[index] === 'struct') {
      index++
      const name = tokens[index++]
      expect('{')
      const rawFields: { name: string; type: TypeRef; padding?: number }[] = []
      while (tokens[index] !== '}') {
        if (tokens[index] === 'pad') {
          index++
          expect('(')
          rawFields.push({ name: '', type: { kind: 'primitive', primitive: 'byte' }, padding: Number(tokens[index++]) })
          expect(')')
          expect(';')
          continue
        }
        let type = parseType(tokens, () => tokens[index++])
        const dimensions: string[] = []
        while (tokens[index] === '[') {
          index++
          dimensions.push(tokens[index++])
          expect(']')
        }
        const fieldName = tokens[index++]
        while (tokens[index] === '[') {
          index++
          dimensions.push(tokens[index++])
          expect(']')
        }
        for (let dimension = dimensions.length - 1; dimension >= 0; dimension--) {
          const token = dimensions[dimension]
          const length = Number.isNaN(Number(token)) ? enums.get(token)?.length : Number(token)
          if (!length) throw new Error(`Unknown array dimension ${token}`)
          type = { kind: 'array', element: type, length }
        }
        expect(';')
        rawFields.push({ name: fieldName, type })
      }
      expect('}')
      expect(';')
      rawStructs.set(name, rawFields)
      continue
    }
    throw new Error(`Unexpected token ${tokens[index]}`)
  }
  const resolving = new Set<string>()
  const resolveStruct = (name: string): StructDefinition => {
    const existing = structs.get(name)
    if (existing) return existing
    const rawFields = rawStructs.get(name)
    if (!rawFields) throw new Error(`Unknown struct ${name}`)
    if (resolving.has(name)) throw new Error(`Circular struct dependency ${name}`)
    resolving.add(name)
    const definition = layoutStruct(rawFields, enums, structs, resolveStruct)
    resolving.delete(name)
    structs.set(name, definition)
    return definition
  }
  root = resolveStruct('root')
  return { enums, structs, root, sizeBits: root.sizeBits }
}

export function parseProfile(data: Uint8Array, definition: Definition): ParsedProfile {
  if (data.length !== profileSize) throw new Error(`Profile must be exactly ${profileSize} bytes`)
  const fields: ProfileField[] = []
  visitStruct(data, definition, definition.root, 32, '', fields)
  const checksum = readUint32BE(data, 0)
  return { fields, checksum, checksumValid: checksum === crc32(data.subarray(4)), definitionSize: Math.ceil(definition.sizeBits / 8) }
}

export function updateProfile(data: Uint8Array, field: ProfileField, value: number | boolean | string): Uint8Array {
  const updated = data.slice()
  if (field.kind === 'bool') setBit(updated, field.offsetBits, Boolean(value))
  else if (field.kind === 'byte') updated[field.offsetBits / 8] = Number(value) & 0xff
  else if (field.kind === 'short') writeUint16LE(updated, field.offsetBits / 8, Number(value))
  else if (field.kind === 'int') writeUint32LE(updated, field.offsetBits / 8, Number(value))
  else if (field.kind === 'enum') writeUint16LE(updated, field.offsetBits / 8, Number(value))
  else writeString(updated, field.offsetBits / 8, String(value), field.length ?? 0)
  writeUint32BE(updated, 0, crc32(updated.subarray(4)))
  return updated
}

function tokenize(source: string): string[] {
  return source.replace(/\/\/.*$/gm, '').match(/"(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z0-9_]*|-?\d+|[{}()[\];,]/g) ?? []
}

function parseType(tokens: string[], next: () => string): TypeRef {
  const token = next()
  if (token === 'string') {
    if (next() !== '(') throw new Error('Expected string length')
    const length = Number(next())
    if (next() !== ')') throw new Error('Expected string terminator')
    return { kind: 'primitive', primitive: 'string', length }
  }
  if (token === 'int' || token === 'short' || token === 'byte' || token === 'bool') return { kind: 'primitive', primitive: token }
  if (!tokens.length) throw new Error('Missing type')
  return { kind: 'named', name: token }
}

function layoutStruct(rawFields: { name: string; type: TypeRef; padding?: number }[], enums: Map<string, string[]>, structs: Map<string, StructDefinition>, resolveStruct: (name: string) => StructDefinition): StructDefinition {
  let offsetBits = 0
  const fields: FieldDefinition[] = []
  for (const raw of rawFields) {
    if (raw.padding !== undefined) {
      offsetBits += raw.padding * 8
      continue
    }
    const alignment = alignmentBits(raw.type)
    offsetBits = align(offsetBits, alignment)
    fields.push({ name: raw.name, type: raw.type, offsetBits })
    offsetBits += sizeBits(raw.type, enums, structs, resolveStruct)
  }
  return { fields, sizeBits: align(offsetBits, 8) }
}

function sizeBits(type: TypeRef, enums: Map<string, string[]>, structs: Map<string, StructDefinition>, resolveStruct?: (name: string) => StructDefinition): number {
  if (type.kind === 'array') return align(type.length * sizeBits(type.element, enums, structs, resolveStruct), 8)
  if (type.kind === 'named') {
    if (enums.has(type.name)) return 16
    const struct = structs.get(type.name) ?? resolveStruct?.(type.name)
    if (!struct) throw new Error(`Unknown type ${type.name}`)
    return struct.sizeBits
  }
  if (type.primitive === 'bool') return 1
  if (type.primitive === 'byte') return 8
  if (type.primitive === 'short') return 16
  if (type.primitive === 'string') return (type.length ?? 0) * 8
  return 32
}

function alignmentBits(type: TypeRef): number {
  if (type.kind === 'array') return alignmentBits(type.element)
  if (type.kind === 'named') return 8
  return type.primitive === 'bool' ? 1 : 8
}

function visitStruct(data: Uint8Array, definition: Definition, struct: StructDefinition, baseBits: number, prefix: string, fields: ProfileField[]) {
  for (const field of struct.fields) visitType(data, definition, field.type, baseBits + field.offsetBits, prefix ? `${prefix}.${field.name}` : field.name, fields)
}

function visitType(data: Uint8Array, definition: Definition, type: TypeRef, offsetBits: number, path: string, fields: ProfileField[]) {
  if (type.kind === 'array') {
    const stride = sizeBits(type.element, definition.enums, definition.structs)
    for (let index = 0; index < type.length; index++) visitType(data, definition, type.element, offsetBits + index * stride, `${path}[${index}]`, fields)
    return
  }
  if (type.kind === 'named') {
    const options = definition.enums.get(type.name)
    if (options) fields.push({ path, kind: 'enum', offsetBits, value: readUint16LE(data, offsetBits / 8), options })
    else visitStruct(data, definition, definition.structs.get(type.name)!, offsetBits, path, fields)
    return
  }
  if (type.primitive === 'bool') fields.push({ path, kind: 'bool', offsetBits, value: getBit(data, offsetBits) })
  else if (type.primitive === 'byte') fields.push({ path, kind: 'byte', offsetBits, value: data[offsetBits / 8] })
  else if (type.primitive === 'short') fields.push({ path, kind: 'short', offsetBits, value: readUint16LE(data, offsetBits / 8) })
  else if (type.primitive === 'int') fields.push({ path, kind: 'int', offsetBits, value: readInt32LE(data, offsetBits / 8) })
  else fields.push({ path, kind: 'string', offsetBits, value: readString(data, offsetBits / 8, type.length ?? 0), length: type.length ?? 0 })
}

function align(value: number, alignment: number) { return Math.ceil(value / alignment) * alignment }
function getBit(data: Uint8Array, offset: number) { return (data[offset >> 3] & (1 << (offset & 7))) !== 0 }
function setBit(data: Uint8Array, offset: number, value: boolean) { const mask = 1 << (offset & 7); data[offset >> 3] = value ? data[offset >> 3] | mask : data[offset >> 3] & ~mask }
function readUint16LE(data: Uint8Array, offset: number) { return data[offset] | (data[offset + 1] << 8) }
function writeUint16LE(data: Uint8Array, offset: number, value: number) { data[offset] = value; data[offset + 1] = value >>> 8 }
function readInt32LE(data: Uint8Array, offset: number) { return new DataView(data.buffer, data.byteOffset + offset, 4).getInt32(0, true) }
function writeUint32LE(data: Uint8Array, offset: number, value: number) { new DataView(data.buffer, data.byteOffset + offset, 4).setUint32(0, value >>> 0, true) }
function readUint32BE(data: Uint8Array, offset: number) { return new DataView(data.buffer, data.byteOffset + offset, 4).getUint32(0, false) }
function writeUint32BE(data: Uint8Array, offset: number, value: number) { new DataView(data.buffer, data.byteOffset + offset, 4).setUint32(0, value >>> 0, false) }
function readString(data: Uint8Array, offset: number, length: number) { const end = data.indexOf(0, offset); return new TextDecoder().decode(data.subarray(offset, end >= offset && end < offset + length ? end : offset + length)) }
function writeString(data: Uint8Array, offset: number, value: string, length: number) { const encoded = new TextEncoder().encode(value); data.fill(0, offset, offset + length); data.set(encoded.subarray(0, Math.max(0, length - 1)), offset) }

export function crc32(data: Uint8Array): number {
  let crc = 0xffffffff
  for (const byte of data) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0)
  }
  return (crc ^ 0xffffffff) >>> 0
}
