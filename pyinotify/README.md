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

若觉得删除操作危险，将Monitor.py中EventHandler类中的DeleteFileOrDir、CanNotDel、CanNotModify函数都注释，仅进行监控操作。

```python
class EventHandler(ProcessEvent):
		"""事件处理"""
		#创建新文件，自动删除
		def process_IN_CREATE(self, event):
			print "[!] Create : " + event.pathname
			#DeleteFileOrDir(event.pathname)

		#文件被删除，如rm命令，自动恢复原文件
		def process_IN_DELETE(self, event):
			print "[!] Delete : " + event.pathname
			# CanNotDel(event.pathname)

		#文件属性被修改，如chmod、chown命令
		def process_IN_ATTRIB(self, event):
			print "[!] Attribute been modified:" + event.pathname

		#文件被移来，如mv、cp命令，自动删除
		def process_IN_MOVED_TO(self, event):
			print "[!] File or dir been moved to here: " + event.pathname
			#DeleteFileOrDir(event.pathname)

		#文件被修改，如vm、echo命令，自动恢复原文件
		def process_IN_MODIFY(self, event):
			print "[!] Modify : " + event.pathname
			#CanNotModify(event.pathname)
```

