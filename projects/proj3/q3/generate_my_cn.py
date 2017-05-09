fid = open("my_cn.dat", "w")
str = "data.gov-of-caltopia.info" + "\x00" + ".neocal.info"
fid.write(str)
fid.close()