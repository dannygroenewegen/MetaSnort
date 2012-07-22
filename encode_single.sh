#!/bin/bash

case $1 in
	h*|-h*|--h* )
		printf "\n HELP \n ---- \n argv1 = amount of samples \n argv2 = amount of encoder runs \n argv3 = (optional) specify encoding \n type 'e' to see available encoders \n\n"
		exit 1
	;;

	e* )
		printf "\nAVAILABLE ENCODERS \n------------------\n`ls -X /opt/framework-3.6.0/msf3/modules/encoders/x86/ | egrep '.rb'`\n------------------\n\n"
		exit 1
	;;
esac

# clean up after the last run and recreate temp-files
touch /tmp/enc.$$ && touch /tmp/res.$$

# check if the encoder is specified, else use shikata_ga_nai
encoder=$3
: ${encoder:="x86/shikata_ga_nai"}
echo using $encoder

# prepare result file
printf "########## \n `date` \n using $encoder, $1 samples, $2 encoder runs \n########## \n" > /tmp/results.txt

# let the encoder run...
for i in `seq 1 $1`
do 
	# print the payload to encode, make a hash, encode it, grep the results, get the unique calls into tempfile
	# string is broken up to get msfencode to be quiet (ugly, we know :-) )
	string=`printf "$i" | md5sum | awk '{ print $1 }' | msfencode -q -e $encoder -c $2` 2> /dev/null
	echo $string | egrep -o '\x..' | sort | uniq >> /tmp/enc.$$ 
done

# count the occurances of each string
for i in `sort /tmp/enc.$$ | uniq`
do 
	count=`egrep -o $i /tmp/enc.$$ | wc -w`
	echo $count $i >> /tmp/res.$$
done

# sort the result list and print them
sort -n /tmp/res.$$ >> /tmp/results.txt
head -4 /tmp/results.txt && tail -10 /tmp/results.txt
printf "... \n full results in /tmp/results.txt \n"

# clean up
rm /tmp/res.$$ && rm /tmp/enc.$$
