## 使用说明

```
pyinotify：Pyinotify是一个Python模块，用来监测文件系统的变化。 

monitor.py: linux文件监控脚本。

运行命令监控/var/www/html/ ：
python monitor.py -w /var/www/html/ 
```

功能：

* 创建新文件，自动删除
* 文件被删除，如rm命令，自动恢复原文件
* 文件属性被修改，如`chmod`、`chown`命令
* 文件被移动到监控目录，如`mv`、`cp`命令，自动删除
* 文件被修改，使用echo命令修改，会恢复文件；使用vim修改则会删除该文件。

个人觉得删除功能有点危险，慎用！