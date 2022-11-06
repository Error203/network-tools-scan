#!/usr/bin/env python3
import argparse

parser = argparse.ArgumentParser(
					prog="scan.py",
					description="simple utilite for scanning network",
					epilog="example:\n\n")
parser.add_argument("-v", "--verbose", action="store_true", help="turn on/off debug")

def main():
	pass

if __name__ == '__main__':
	main()
