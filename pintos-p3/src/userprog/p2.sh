#!/bin/bash

# This grading script is intended to show students what would happen when TA
# grade p2 project.
#
# Do the following steps to run the script:
# - copy this script to src/userprog/
#
# - change file attribute to allow script execution
#
#   chmod 700 p2.sh
#
# - run this script to start grading
#
#   ./p2.sh
#
# This script will download pintos-raw and extract it to ~/cs230-grading/pintos,
# copy specific files that you are allowed to modify there, and do the grading
# on ~/cs230-grading/pintos.

cd ../

rm -rf ~/cs230-grading &> /dev/null

# Download the pintos-raw code and extract it.
wget https://www.classes.cs.uchicago.edu/archive/2018/fall/23000-1/proj/files/pintos-raw.tgz -P ~/cs230-grading
tar -zxvf ~/cs230-grading/pintos-raw.tgz -C ~/cs230-grading/
rm ~/cs230-grading/pintos-raw.tgz
mv ~/cs230-grading/pintos-raw ~/cs230-grading/pintos


# Determine the acceptable changed files and copy it from the student directory
# to the temporary grading directory.
files=(threads/thread.c
       threads/thread.h
       userprog/exception.c
       userprog/process.c
       userprog/syscall.c
       userprog/syscall.h)

for file in ${files[@]}; do
    cp $file ~/cs230-grading/pintos/src/$file
done

cd ~/cs230-grading/pintos/src/userprog/

make 2> /dev/null

cd build/

make check 

calc() {
echo "scale=4; $1" | bc ;exit
}

make check > check_output
sum=0
sum2=0
sumFunc=0
sumRob=0
sumNov=0
sumBas=0
indexChecker() {
sum=0

if [ "$1" -eq 0 ] || [ "$1" -eq 1 ] || [ "$1" -eq 2 ] || [ "$1" -eq 3 ] || [ "$1" -eq 4 ] || [ "$1" -eq 5 ] || [ "$1" -eq 6 ] || [ "$1" -eq 9 ] || [ "$1" -eq 11 ] || [ "$1" -eq 12 ] || [ "$1" -eq 14 ] || [ "$1" -eq 15 ] || [ "$1" -eq 16 ] || [ "$1" -eq 19 ] || [ "$1" -eq 18 ] || [ "$1" -eq  24 ] || [ "$1" -eq 30 ] || [ "$1" -eq 33 ] || [ "$1" -eq 36 ] || [ "$1" -eq 39 ] || [ "$1" -eq 25 ] || [ "$1" -eq 53 ] || [ "$1" -eq 54 ] || [ "$1" -eq 55 ] || [ "$1" -eq 46 ] || [ "$1" -eq 23 ] || [ "$1" -eq 31 ] || [ "$1" -eq 37 ] || [ "$1" -eq 17 ] || [ "$1" -eq 20 ] || [ "$1" -eq 32 ] || [ "$1" -eq 38 ] || [ "$1" -eq 72 ] || [ "$1" -eq 67 ]
then sum=$(($sum+3));
else if [ "$1" -eq 42 ] || [ "$1" -eq 44 ] || [ "$1" -eq 43 ] || [ "$1" -eq 47 ] || [ "$1" -eq 48 ] || [ "$1" -eq 10 ] || [ "$1" -eq 7 ] || [ "$1" -eq 8 ] || [ "$1" -eq 45 ] || [ "$1" -eq 50 ] || [ "$1" -eq 49 ]
then sum=$(($sum+5));
else if [ "$1" -eq 27 ] ||  [ "$1" -eq 28 ] || [ "$1" -eq 29 ] || [ "$1" -eq 26 ] || [ "$1" -eq 35 ] || [ "$1" -eq 34 ] || [ "$1" -eq 41 ] || [ "$1" -eq 40 ] || [ "$1" -eq 52 ] || [ "$1" -eq 13 ] || [ "$1" -eq 22 ] || [ "$1" -eq 21 ] || [ "$1" -eq 69 ] || [ "$1" -eq 70 ] || [ "$1" -eq 71 ] || [ "$1" -eq 64 ] || [ "$1" -eq 65 ] || [ "$1" -eq 66 ] || [ "$1" -eq 74 ]
then sum=$(($sum+2));
else if [ "$1" -eq 68 ] || [ "$1" -eq 63 ] || [ "$1" -eq 56 ] || [ "$1" -eq 57 ] || [ "$1" -eq 60 ] || [ "$1" -eq 58 ] || [ "$1" -eq 59 ] || [ "$1" -eq 61 ] || [ "$1" -eq 62 ]
then sum=$(($sum+1));
else if [ "$1" -eq 73 ] || [ "$1" -eq 75 ]
then sum=$(($sum+4));
else if [ "$1" -eq 51 ]
then sum=$(($sum+15));
fi
fi
fi
fi
fi
fi

if [ "$1" -eq 0 ] || [ "$1" -eq 1 ] || [ "$1" -eq 2 ] || [ "$1" -eq 3 ] || [ "$1" -eq 4 ] || [ "$1" -eq 9 ] || [ "$1" -eq 10 ] || [ "$1" -eq 11 ] || [ "$1" -eq 12 ] || [ "$1" -eq 15 ] || [ "$1" -eq 16 ] || [ "$1" -eq 18 ] || [ "$1" -eq 19 ] || [ "$1" -eq 24 ] || [ "$1" -eq 25 ] || [ "$1" -eq 30 ] || [ "$1" -eq 33 ] || [ "$1" -eq 36 ] || [ "$1" -eq 39 ] || [ "$1" -eq 42 ] || [ "$1" -eq 43 ] || [ "$1" -eq 44 ] || [ "$1" -eq 47 ] || [ "$1" -eq 48 ] || [ "$1" -eq 51 ] || [ "$1" -eq 53 ] || [ "$1" -eq 54 ] || [ "$1" -eq 55 ]
then sumFunc=$(($sumFunc+$sum));
  sum=$(($sum*35));

else if [ "$1" -eq 13 ] || [ "$1" -eq 14 ] || [ "$1" -eq 17 ] || [ "$1" -eq 20 ] || [ "$1" -eq 21 ] || [ "$1" -eq 22 ] || [ "$1" -eq 23 ] || [ "$1" -eq 26 ] || [ "$1" -eq 27 ] || [ "$1" -eq 28 ] || [ "$1" -eq 29 ] || [ "$1" -eq 31 ] || [ "$1" -eq 32 ] || [ "$1" -eq 34 ] || [ "$1" -eq 35 ] || [ "$1" -eq 37 ] || [ "$1" -eq 38 ] ||  [ "$1" -eq 40 ] || [ "$1" -eq 41 ] || [ "$1" -eq 46 ] || [ "$1" -eq 52 ] || [ "$1" -eq 56 ] || [ "$1" -eq 57 ] || [ "$1" -eq 58 ] || [ "$1" -eq 59 ] || [ "$1" -eq 60 ] || [ "$1" -eq 61 ] || [ "$1" -eq 50 ] || [ "$1" -eq 49 ] || [ "$1" -eq 45 ] || [ "$1" -eq 8 ] || [ "$1" -eq 7 ] || [ "$1" -eq 6 ] || [ "$1" -eq 5 ]
then sumRob=$(($sumRob+$sum));
  sum=$(($sum*25));

else if [ "$1" -eq 62 ]
then sumNov=$(($sumNov+$sum));
   sum=$(($sum*10));

 else if [ "$1" -eq 63 ] || [ "$1" -eq 64 ] || [ "$1" -eq 65 ] || [ "$1" -eq 66 ] || [ "$1" -eq 67 ] || [ "$1" -eq 68 ] || [ "$1" -eq 69 ] || [ "$1" -eq 70 ] || [ "$1" -eq 71 ] || [ "$1" -eq 72 ] || [ "$1" -eq 73 ] || [ "$1" -eq 74 ] || [ "$1" -eq 75 ]
 then sumBas=$(($sumBas+$sum));
    sum=$(($sum*30));
  fi
fi
fi
fi
sum2=$(($sum2+$sum));

}

i=0
while read line
do
pass=$(echo $line | grep "pass");
if [ -z "$pass" ]
  then
    sum=$sum;
  else
    indexChecker $i
fi

i=$(($i+1));

done < "check_output"
                
grade=$(calc $sum2/100);
grade90=$(calc $(calc $grade*90)/68.9);


echo "sum of functionality tests is: $sumFunc (108) emphasis: 35%";
echo "sum of robustness tests is: $sumRob (88)  emphasis: 25%";
echo "sum of no vm test is: $sumNov (1) emphasis: 10%";
echo "sum of base tests is: $sumBas (30) emphasis: 30%";
echo "Total sum is: $sum2";
echo "Total grade: $grade";
echo "Total grade out of 90: $grade90";

# Delete the temporary grading directory.
rm -rf ~/cs230-grading &> /dev/null
