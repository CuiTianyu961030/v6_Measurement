#./bin/sh
#date 20150903 by zlw


dir='/home/guoyu/1_sapp/'

business_dir='plug/business/'
plugin_type='sapp'
plugin_dir=$dir$business_dir
plugin_dir_inf_name=$plugin_dir'conflist_business.inf'

plugin_name='ssl_capture' 
plugin_dest='*.inf *.so'

log_dir='/home/guoyu/ssl_log/'
log_name=$log_dir'ssl_json'
rm $log_name
echo -e '\e[0;30;1m''remove the old log successfully~''\e[0m'
echo -e '\e[0;31;1m''Begin''\e[0m'
if [ -d $dir -a -d $plugin_dir ]
	then
		if [ ! -d  $plugin_dir$plugin_name ]	
		then
		echo '\t\tCreate dir '$plugin_dir$plugin_name 
		mkdir $plugin_dir$plugin_name	
		fi	
else
		echo -e '\e[0;31;1m''dir is error,please modify the dir\ndone && fail''\e[0m'
		exit 1
fi

echo 'make clean & make'
make clean
make > temp
if [ $? -ne 0 ]
then 
    cat temp
	echo -e '\e[0;31;1m''make error && fail''\e[0m'
	exit 1
fi
#copy to dest dir
cp $plugin_dest  $plugin_dir$plugin_name

#copy dir to plug inf

if [ -f $plugin_dir_inf_name ]
then
	re=`grep -cx './'$business_dir$plugin_name'/'$plugin_name'.inf' $plugin_dir_inf_name` 
	if [ $re -eq 0 ]
	then
		 echo './'$business_dir$plugin_name'/'$plugin_name'.inf'   >> $plugin_dir_inf_name
	fi
	
	
else
	echo  -e '\e[0;31;1m''$plugin_dir_inf_name is not existed,we create it''\e[0m'
	touch	$plugin_dir_inf_name
	echo './'$business_dir$plugin_name'/'$plugin_name'.inf'   >> $plugin_dir_inf_name
fi

echo -e '\e[0;31;1m''done && success''\e[0m'

echo '--------------------------------------'

if [ $# -eq 0 ] 
then
    echo -e '\e[0;31;1m''now run''\e[0m'
    echo '--------------------------------------'
    cd $dir
    ./$plugin_type
else
    exit 2
fi

echo '--------------------------------------'
exit 0


