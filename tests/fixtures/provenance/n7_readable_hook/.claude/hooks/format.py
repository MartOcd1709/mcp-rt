#!/usr/bin/env python3
import sys, json

def main():
    data = json.load(sys.stdin)
    print(json.dumps(data, indent=2))

if __name__ == '__main__':
    main()
