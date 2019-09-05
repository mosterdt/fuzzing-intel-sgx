#!/bin/sh
echo Initialize environment

source /home/thomas/kuleuven/thesis/intel/sgxsdk/environment

echo Build fuzzer instance

cd fuzzer
make clean
make

echo Running fuzzer, this can take a while
sudo ./run 3 > ../data/data_demo.csv

echo Analysing data
cd ../data
python3 modify_data.py data_demo.csv
Rscript graph_data.r 1
rm data_demo_1.csv data_demo_2.csv

echo Displaying result
zathura graph_demo.pdf

cd ..

