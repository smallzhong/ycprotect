# ycprotect

## 注意

+ 由于本项目为学习使用，并没有做对各个系统版本的兼容。很多结构的偏移都是直接使用了硬编码。如果想要使用本项目中的代码请搜索 `TODO:` 找到标记本处使用了硬编码的 `TODO` ，然后修改使其兼容各个版本。本项目基于 `win7` 32位开发。

## 功能

+ 句柄降权，根据pid遍历所有当前进程中的句柄表。如果发现句柄表中打开了需要保护的进程，则抹去其对受保护进程的读写权限，从而达到降权的效果。在执行句柄降权之后可以让CE、OD在调试时无法访问对应的内存。



## 使用方法

+ 首先定义符号名称、请求号、请求码

  ```cpp
  // 符号名称，固定写法
  #define SYM_NAME "\\\\.\\smallzhong"
  
  // 请求号，自定义请求号从0x800开始
  #define CODE_句柄降权 0x800
  
  // 请求
  #define CTL_句柄降权 CTL_CODE(FILE_DEVICE_UNKNOWN, CODE_句柄降权, METHOD_BUFFERED, FILE_ANY_ACCESS)
  ```

### 句柄降权

+ 向驱动传递需要保护的进程的pid，开启降权线程

  ```cpp
  BOOLEAN 句柄降权_pid(ULONG pid)
  {
  	HANDLE hDevice = CreateFileA(SYM_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  
  	ULONG BytesReturned = 0;
  
  	BOOLEAN status = DeviceIoControl(hDevice, CTL_句柄降权, &pid, 4, NULL, NULL, &BytesReturned, NULL);
  
  	printf("status = %d\n", status);
  
  	CloseHandle(hDevice);
  
  	return status;
  }
  
  int main()
  {
      BOOLEAN status = 句柄降权_pid(2748);
  }
  ```

## TODO：

- [ ] 优化句柄降权，遍历进程时提高效率