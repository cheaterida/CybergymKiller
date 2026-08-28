from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .blueprints import BLUEPRINTS, get_blueprint, get_template_bytes
from .catalog import FORMATS, get_format, list_formats
from .containers import build_container, diagnose_container, mutate_field, sample as build_sample
from .matcher import diagnose_formats, identify_families, match_formats, parse_header
from .validation import run_template_validators, validate_file


def _json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def _json_input(inline: str | None, path: Path | None) -> dict[str, object]:
    if inline and path:
        raise ValueError("use either inline JSON or a JSON file, not both")
    if path:
        value = json.loads(path.read_text(encoding="utf-8"))
    else:
        value = json.loads(inline or "{}")
    if not isinstance(value, dict):
        raise ValueError("container specification/mutation must be a JSON object")
    return value


def _container_metadata(result: dict[str, object], output: Path) -> dict[str, object]:
    return {key: value for key, value in result.items() if key not in {"bytes", "hex"}} | {"output": str(output)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="format-kb", description=f"Match, diagnose and describe {len(FORMATS)} file and protocol formats")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="List all format records without long structure strings")
    commands.add_parser("stats", help="Show catalog counts")
    describe = commands.add_parser("describe", help="Print the exact compact structure string for an Agent")
    describe.add_argument("format")
    blueprint = commands.add_parser("blueprint", help="Print defaults, dependencies, minimal HEX template and parser-risk fields")
    blueprint.add_argument("format")
    blueprint.add_argument("--json", action="store_true", help="Emit the same blueprint as machine-readable JSON")
    template = commands.add_parser("template", help="Export a verified static template as HEX, hex dump, C array or raw bytes")
    template.add_argument("format")
    template.add_argument("--encoding", choices=("hex", "hexdump", "c-array", "raw"), default="hex")
    template.add_argument("--output", type=Path, help="Write output to a file; required for raw bytes")
    template.add_argument("--allow-incomplete", action="store_true", help="Allow exporting a signature prefix that is not a legal file")
    template.add_argument("--allow-unverified", action="store_true", help="Allow a complete template that has only type-level validation")
    template.add_argument("--force", action="store_true", help="Allow replacing an existing output file")
    validate = commands.add_parser("validate", help="Validate a file against a format or signature-prefix rule")
    validate.add_argument("format")
    validate.add_argument("file", type=Path)
    validate.add_argument("--prefix-only", action="store_true")
    validate.add_argument("--run-declared", action="store_true", help="Run all declared validator commands instead of only the internal validator")
    show = commands.add_parser("show", help="Print the complete machine-readable format record")
    show.add_argument("format")
    match = commands.add_parser("match", help="Rank formats from header magic and/or extension")
    header = match.add_mutually_exclusive_group()
    header.add_argument("--hex", default="", help="Header bytes as hexadecimal")
    header.add_argument("--ascii", help="Header bytes as literal UTF-8 text")
    header.add_argument("--file", type=Path, help="Read the first --bytes bytes from a file")
    match.add_argument("--bytes", type=int, default=1024 * 1024, help="Maximum bytes read with --file")
    match.add_argument("--ext", help="Extension or filename")
    match.add_argument("--limit", type=int, default=10)
    match.add_argument("--no-structure", action="store_true")
    match.add_argument("--diagnose", action="store_true", help="Return nearest failed format checks when no format matches")
    diagnose = commands.add_parser("diagnose", help="Show the nearest failed magic/probe checks")
    diagnose.add_argument("--hex", default="", help="Header bytes as hexadecimal")
    diagnose.add_argument("--ext", help="Extension or filename")
    diagnose.add_argument("--limit", type=int, default=5)
    family = commands.add_parser("family", help="Identify RIFF, ISO BMFF, EBML or Ogg family and member candidates")
    family_header = family.add_mutually_exclusive_group(required=True)
    family_header.add_argument("--hex", help="Header bytes as hexadecimal")
    family_header.add_argument("--file", type=Path, help="Read up to 1 MiB from a file")
    container_build = commands.add_parser("container-build", help="Build a deterministic variable-layout container from JSON")
    container_build.add_argument("format")
    container_build.add_argument("--spec", help="Inline JSON object")
    container_build.add_argument("--spec-file", type=Path, help="Read the JSON object from a file")
    container_build.add_argument("--output", type=Path, required=True)
    container_build.add_argument("--force", action="store_true")
    container_capabilities = commands.add_parser("container-capabilities", help="List variable-layout formats and their exact supported subsets")
    container_capabilities.add_argument("format", nargs="?")
    container_diagnose = commands.add_parser("container-diagnose", help="Parse container layers and report the first structural failure")
    container_diagnose.add_argument("format")
    container_diagnose.add_argument("file", type=Path)
    container_mutate = commands.add_parser("container-mutate", help="Mutate a semantic field and rebuild dependent layout/checksums")
    container_mutate.add_argument("format")
    container_mutate.add_argument("file", type=Path)
    container_mutate.add_argument("--mutation", help="Inline mutation JSON")
    container_mutate.add_argument("--mutation-file", type=Path)
    container_mutate.add_argument("--output", type=Path, required=True)
    container_mutate.add_argument("--force", action="store_true")
    sample = commands.add_parser("sample", help="Generate a deterministic representative format instance")
    sample.add_argument("format")
    sample.add_argument("--options", help="Inline options JSON")
    sample.add_argument("--options-file", type=Path)
    sample.add_argument("--output", type=Path, required=True)
    sample.add_argument("--force", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list":
            _json(list_formats())
        elif args.command == "stats":
            categories: dict[str, int] = {}
            for item in FORMATS:
                categories[item.category] = categories.get(item.category, 0) + 1
            _json(
                {
                    "formats": len(FORMATS),
                    "categories": categories,
                    "with_magic": sum(bool(item.magic) for item in FORMATS),
                    "with_probe": sum(bool(item.probe) for item in FORMATS),
                    "blueprints": len(BLUEPRINTS),
                    "complete_minimal_templates": sum(item.minimal_template.status == "complete" for item in BLUEPRINTS),
                    "verified_minimal_templates": sum(item.minimal_template.validation_status == "verified" for item in BLUEPRINTS),
                    "risk_profiles": len({warning.profile for item in BLUEPRINTS for warning in item.warnings}),
                }
            )
        elif args.command == "describe":
            print(get_format(args.format).structure)
        elif args.command == "blueprint":
            item = get_blueprint(args.format)
            _json(item.to_dict()) if args.json else print(item.render())
        elif args.command == "template":
            item = get_blueprint(args.format)
            data = get_template_bytes(
                args.format,
                allow_incomplete=args.allow_incomplete,
                allow_unverified=args.allow_unverified,
            )
            if args.output and args.output.exists() and not args.force:
                raise ValueError(f"output already exists: {args.output}; pass --force to replace it")
            if args.encoding == "raw":
                if not args.output:
                    raise ValueError("--output is required with --encoding raw")
                args.output.write_bytes(data)
            else:
                if args.encoding == "hex":
                    rendered = data.hex().upper()
                elif args.encoding == "hexdump":
                    rendered = "\n".join(
                        f"{offset:08X}  "
                        + " ".join(f"{byte:02X}" for byte in data[offset : offset + 16]).ljust(47)
                        + "  |"
                        + "".join(chr(byte) if 32 <= byte < 127 else "." for byte in data[offset : offset + 16])
                        + "|"
                        for offset in range(0, len(data), 16)
                    )
                else:
                    identifier = re.sub(r"[^0-9A-Za-z_]", "_", item.spec.id)
                    rows = [", ".join(f"0x{byte:02X}" for byte in data[offset : offset + 12]) for offset in range(0, len(data), 12)]
                    rendered = (
                        f"static const unsigned char format_kb_{identifier}[] = {{\n"
                        + "\n".join(f"    {row}," for row in rows)
                        + f"\n}};\nstatic const unsigned long format_kb_{identifier}_len = {len(data)}UL;"
                    )
                if args.output:
                    args.output.write_text(rendered + "\n", encoding="utf-8")
                else:
                    print(rendered)
        elif args.command == "validate":
            if args.run_declared:
                results = run_template_validators(args.format, args.file)
                _json({"format_id": get_format(args.format).id, "valid": bool(results) and all(item.get("passed") for item in results), "validators": results})
                return 0 if results and all(item.get("passed") for item in results) else 1
            result = validate_file(args.format, args.file, prefix_only=args.prefix_only)
            _json(result)
            return 0 if result["valid"] else 1
        elif args.command == "diagnose":
            data = parse_header(args.hex)
            _json([item.to_dict() for item in diagnose_formats(data, args.ext, limit=args.limit)])
        elif args.command == "family":
            if args.file:
                with args.file.open("rb") as stream:
                    data = stream.read(1024 * 1024)
            else:
                data = parse_header(args.hex)
            families = identify_families(data)
            _json([item.to_dict() for item in families])
            return 0 if families else 1
        elif args.command == "container-build":
            if args.output.exists() and not args.force:
                raise ValueError(f"output already exists: {args.output}; pass --force to replace it")
            result = build_container(args.format, _json_input(args.spec, args.spec_file))
            args.output.write_bytes(result["bytes"])
            _json(_container_metadata(result, args.output))
        elif args.command == "container-capabilities":
            from .containers import container_capabilities

            _json(container_capabilities(args.format))
        elif args.command == "container-diagnose":
            result = diagnose_container(args.file.read_bytes(), args.format)
            _json(result)
            return 0 if result["valid"] else 1
        elif args.command == "container-mutate":
            if args.output.exists() and not args.force:
                raise ValueError(f"output already exists: {args.output}; pass --force to replace it")
            result = mutate_field(args.file.read_bytes(), args.format, _json_input(args.mutation, args.mutation_file))
            args.output.write_bytes(result["bytes"])
            _json(_container_metadata(result, args.output))
        elif args.command == "sample":
            if args.output.exists() and not args.force:
                raise ValueError(f"output already exists: {args.output}; pass --force to replace it")
            result = build_sample(args.format, _json_input(args.options, args.options_file))
            args.output.write_bytes(result["bytes"])
            _json(_container_metadata(result, args.output))
        elif args.command == "show":
            _json(get_format(args.format).to_dict())
        elif args.command == "match":
            if args.file:
                if args.bytes <= 0 or args.bytes > 16 * 1024 * 1024:
                    raise ValueError("--bytes must be between 1 and 16777216")
                with args.file.open("rb") as stream:
                    data = stream.read(args.bytes)
                extension = args.ext or args.file.name
            elif args.ascii is not None:
                data = args.ascii.encode("utf-8")
                extension = args.ext
            else:
                data = parse_header(args.hex)
                extension = args.ext
            matches = match_formats(data, extension, limit=args.limit)
            serialized = [item.to_dict(include_structure=not args.no_structure) for item in matches]
            if args.diagnose:
                _json({"matches": serialized, "diagnosis": [] if matches else [item.to_dict() for item in diagnose_formats(data, extension, limit=5)]})
            else:
                _json(serialized)
            return 0 if matches else 1
        return 0
    except (IndexError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
