import uzlib as zlib
import ql_fs
import app_fota_download
from usr.common import Abstract
from usr import EventMesh
import osTimer


class FileDecode(object):
    def __init__(self, zip_file, parent_dir="/fota/usr/"):
        self.data = b''
        self.fp = open(zip_file, "rb")
        self.fileData = None
        self.parent_dir = parent_dir
        self.update_file_list = []

    def get_update_files(self):
        return self.update_file_list

    def unzip(self):
        """缓存到内存中"""
        self.fp.seek(10)
        self.fileData = zlib.DecompIO(self.fp, -15)

    @classmethod
    def _ascii_trip(cls, data):
        return data.decode('ascii').rstrip('\0')

    @classmethod
    def file_size(cls, data):
        """获取真实size数据"""
        size = cls._ascii_trip(data)
        if not len(size):
            return 0
        return int(size, 8)

    @classmethod
    def get_file_name(cls, file_name):
        """获取文件名称"""
        return cls._ascii_trip(file_name)

    def get_data(self):
        return self.fileData.read(0x200)

    def unpack(self):
        try:
            folder_list = set()
            self.data = self.get_data()
            while True:
                if not self.data:
                    print("no data")
                    break
                print(self.data[124:135])
                size = self.file_size(self.data[124:135])
                file_name = "/usr/" + self.get_file_name(self.data[:100])
                full_file_name = self.parent_dir + file_name

                if not size:
                    if len(full_file_name):
                        ql_fs.mkdirs(full_file_name)
                        if full_file_name not in folder_list and full_file_name != self.parent_dir:
                            folder_list.add(full_file_name)
                            print("Folder {} CREATED".format(full_file_name))
                    else:
                        return
                    self.data = self.get_data()
                else:
                    print("FILE {} WRITE BYTE SIZE = {}".format(full_file_name, size))
                    self.data = self.get_data()
                    update_file = open(full_file_name, "wb+")
                    total_size = size
                    while True:
                        size -= 0x200
                        if size <= 0:
                            update_file.write(self._ascii_trip(self.data))
                            break
                        else:
                            update_file.write(self.data)
                        self.data = self.get_data()
                    self.data = self.get_data()
                    update_file.close()
                    self.update_file_list.append({"file_name": file_name, "size": total_size})
        except Exception as e:
            print("unpack error = {}".format(e))
            return False
        else:
            return True

    def update_stat(self):
        for f in self.update_file_list:
            print("f = {}".format(f))
            app_fota_download.update_download_stat(f["file_name"], f["file_name"], f["size"])

    @staticmethod
    def set_flag():
        with open(app_fota_download.get_update_flag_file(), "w") as f:
            f.write("{upgrade}")


def run_unzip_upgrade(tar_src="usr/code.tar.gz"):
    app_fota_download.app_fota_pkg_mount.mount_disk()
    ###########设置fota的压缩包所在位置, fota的目录并解压缩#####################
    tar_src = "usr/code.tar.gz"
    fd = FileDecode(tar_src, parent_dir=app_fota_download.get_updater_dir())
    fd.unzip()
    stat = fd.unpack()
    if stat:
        ############解压成功, 更新文件校验crc32, 删除tar包############
        # uos.remove(tar_src)
        fd.update_stat()
        fd.set_flag()
        ##############用户重启######################
        # Power...RESTART 操作
        return True
    else:
        ###############解压失败################
        return False


class FtpOtaManager(Abstract):
    '''
    ftp 远程升级app
    '''

    def __init__(self):
        self.parent_dir = "usr/"
        self.file_name = "code.tar.gz"
        self.host = "139.224.27.107"
        self.port = 21
        self.ftp = None
        self.user = "user"
        self.passwd = "userpwd"

    def post_processor_before_initialization(self):
        EventMesh.subscribe("ftp_upgrade", self.download)

    def download(self, topic, msg):
        from ftplib import FTP
        self.ftp = FTP()
        connect_res = self.ftp.connect(host=self.host, port=self.port)
        print("ftp.connect(): %s" % connect_res)
        login_res = self.ftp.login(user=self.user, passwd=self.passwd)
        print("ftp.login(): %s" % login_res)
        fp = open(self.parent_dir + self.file_name, "wb")
        server_path = self.ftp.pwd()
        res = self.ftp.retrbinary("RETR " + server_path + "/" + self.file_name, fp.write)
        msg = "Download %s to device %s."
        if res.startswith('226 Transfer complete'):
            print(msg % (self.file_name, "success"))
            app_fota_download.app_fota_pkg_mount.mount_disk()
            fd = FileDecode(self.parent_dir + self.file_name, parent_dir=app_fota_download.get_updater_dir())
            fd.unzip()
            stat = fd.unpack()
            if stat:
                fd.update_stat()
                fd.set_flag()
                # 重启设备升级
                print("success")
            else:
                print("failed")
                pass
        else:
            print(msg % (self.file_name, "falied"))
        fp.close()


class UartOtaManager(object):
    '''
    串口 远程升级app
    '''

    def __init__(self):
        pass


class ServerOtaManager(object):
    '''
    通过主站经电表 远程升级app
    '''

    def __init__(self):
        pass
