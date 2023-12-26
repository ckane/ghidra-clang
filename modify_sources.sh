#!/bin/bash
src="$1"

sed -i "s/ processEntry / /" "$src"
