#!/bin/bash
#SBATCH --job-name=duplicate_scan
#SBATCH --time=08:00:00
#SBATCH --cpus-per-task=4
#SBATCH --mem=16G
#SBATCH --output=duplicate_scan_%j.out
#SBATCH --error=duplicate_scan_%j.err

cd /path/to/working_directory
python duplicate_scan.py /path/to/target
