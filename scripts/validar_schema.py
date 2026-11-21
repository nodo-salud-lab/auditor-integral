#!/usr/bin/env python3
"""Validador mínimo de JSON Schema (draft 2020-12), solo biblioteca estándar.

Soporta el subconjunto que usan los schemas del auditor:
type, required, properties, enum, const, items, maxLength, minLength, pattern,
additionalProperties, minimum, maximum, minItems, $ref (solo "#/$defs/<nombre>").

Uso:
    validar_schema.py [--def NOMBRE] SCHEMA.json ARCHIVO.(json|jsonl) [...]
Código de salida: 0 si todo valida, 1 si hay errores, 2 si hay error de uso.
"""
import argparse
import json
import re
import sys
from pathlib import Path

# Palabras clave que se interpretan (validan) y anotaciones que se ignoran.
SOPORTADAS = {
    "type", "required", "properties", "enum", "const", "items", "maxLength", "minLength",
    "pattern", "additionalProperties", "minimum", "maximum", "minItems", "$ref",
}
ANOTACIONES = {"$schema", "$id", "$defs", "title", "description", "$comment", "examples", "default"}

FALTA = object()  # centinela para tests (quitar una clave)

_TIPOS = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
}


def _resolver_ref(ref, raiz):
    if not ref.startswith("#/$defs/"):
        raise ValueError(f"$ref no soportado: {ref}")
    nombre = ref[len("#/$defs/"):]
    try:
        return raiz["$defs"][nombre]
    except KeyError as exc:
        raise ValueError(f"$ref no encontrado: {ref}") from exc


def validar(instancia, schema, raiz=None, ruta=""):
    """Devuelve la lista de errores (vacía si la instancia es válida)."""
    if raiz is None:
        raiz = schema
    errores = []
    if schema is True or schema == {}:
        return errores
    if schema is False:
        return [f"{ruta or '/'}: no se admite ningún valor"]

    if "$ref" in schema:
        errores += validar(instancia, _resolver_ref(schema["$ref"], raiz), raiz, ruta)

    donde = ruta or "/"
    if "type" in schema:
        tipos = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_TIPOS[t](instancia) for t in tipos):
            return errores + [f"{donde}: se esperaba tipo {tipos}, se obtuvo {type(instancia).__name__}"]

    if "enum" in schema and instancia not in schema["enum"]:
        errores.append(f"{donde}: valor {instancia!r} fuera de enum {schema['enum']}")
    if "const" in schema and instancia != schema["const"]:
        errores.append(f"{donde}: se esperaba {schema['const']!r}")

    if isinstance(instancia, str):
        if "maxLength" in schema and len(instancia) > schema["maxLength"]:
            errores.append(f"{donde}: largo {len(instancia)} > maxLength {schema['maxLength']}")
        if "minLength" in schema and len(instancia) < schema["minLength"]:
            errores.append(f"{donde}: largo {len(instancia)} < minLength {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], instancia):
            errores.append(f"{donde}: {instancia!r} no cumple el patrón {schema['pattern']}")

    if _TIPOS["number"](instancia):
        if "minimum" in schema and instancia < schema["minimum"]:
            errores.append(f"{donde}: {instancia} < minimum {schema['minimum']}")
        if "maximum" in schema and instancia > schema["maximum"]:
            errores.append(f"{donde}: {instancia} > maximum {schema['maximum']}")

    if isinstance(instancia, dict):
        for clave in schema.get("required", []):
            if clave not in instancia:
                errores.append(f"{donde}: falta la propiedad requerida '{clave}'")
        props = schema.get("properties", {})
        for clave, valor in instancia.items():
            sub = f"{ruta}/{clave}"
            if clave in props:
                errores += validar(valor, props[clave], raiz, sub)
            elif "additionalProperties" in schema:
                adicional = schema["additionalProperties"]
                if adicional is False:
                    errores.append(f"{sub}: propiedad no permitida")
                elif isinstance(adicional, dict):
                    errores += validar(valor, adicional, raiz, sub)

    if isinstance(instancia, list):
        if "minItems" in schema and len(instancia) < schema["minItems"]:
            errores.append(f"{donde}: {len(instancia)} elementos < minItems {schema['minItems']}")
        if "items" in schema:
            for i, elem in enumerate(instancia):
                errores += validar(elem, schema["items"], raiz, f"{ruta}/{i}")
    return errores


def palabras_no_soportadas(schema):
    """Palabras clave usadas en el schema que este validador no entiende."""
    encontradas = set()

    def recorrer(s):
        if not isinstance(s, dict):
            return
        for clave, valor in s.items():
            if clave not in SOPORTADAS and clave not in ANOTACIONES:
                encontradas.add(clave)
            if clave in ("properties", "$defs"):
                for sub in valor.values():
                    recorrer(sub)
            elif clave in ("items", "additionalProperties"):
                recorrer(valor)

    recorrer(schema)
    return encontradas


def subschema(raiz, nombre_def):
    """Schema de un $defs conservando $defs para resolver $ref."""
    sub = dict(raiz["$defs"][nombre_def])
    sub["$defs"] = raiz["$defs"]
    return sub


def leer_instancias(ruta):
    """Lee un .json (una instancia) o un .jsonl (una por línea no vacía)."""
    ruta = Path(ruta)
    texto = ruta.read_text(encoding="utf-8")
    if ruta.suffix == ".jsonl":
        return [json.loads(linea) for linea in texto.splitlines() if linea.strip()]
    return [json.loads(texto)]


def main(argv=None):
    p = argparse.ArgumentParser(description="Valida JSON/JSONL contra un JSON Schema (subconjunto).")
    p.add_argument("--def", dest="nombre_def", help="validar contra #/$defs/NOMBRE del schema")
    p.add_argument("schema")
    p.add_argument("archivos", nargs="+")
    args = p.parse_args(argv)

    try:
        schema = json.loads(Path(args.schema).read_text(encoding="utf-8"))
        if args.nombre_def:
            schema = subschema(schema, args.nombre_def)
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: no se pudo leer el schema: {exc}", file=sys.stderr)
        return 2

    total = 0
    for archivo in args.archivos:
        try:
            instancias = leer_instancias(archivo)
        except (OSError, ValueError) as exc:
            print(f"{archivo}: no se pudo leer: {exc}")
            total += 1
            continue
        for i, inst in enumerate(instancias):
            for err in validar(inst, schema):
                print(f"{archivo}#{i}: {err}")
                total += 1
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
