import argparse

from .app import Specter


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="specter",
        description="SPECTER - low-touch recon console for authorized engagements.",
    )
    parser.add_argument("target", nargs="?", help="domain to prefill in the target bar")
    args = parser.parse_args()
    Specter(target=args.target).run()


if __name__ == "__main__":
    main()
