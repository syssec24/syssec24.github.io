# 浙江大学23年夏系统安全实验

---

![](img/system-hacked.jpg){ loading=lazy }

---

本[仓库](https://gitee.com/zjusec/syssec-stu)是浙江大学23年夏**系统安全**课程的教学仓库，包含在系统安全课程上所有的实验文档和公开代码。仓库目录结构：

```bash
├── README.md
├── docs/       # 实验文档
└── mkdocs.yml
```

实验文档已经部署在了[gitee pages](https://zjusec.gitee.io/syssec-stu)上，方便大家阅读。


## 本地渲染文档

文档采用了 [mkdocs-material](https://squidfunk.github.io/mkdocs-material) 工具构建和部署。如果想在本地渲染：

```bash
$ pip3 install mkdocs-material                      # 安装 mkdocs-material
$ git clone https://gitee.com/zjusec/syssec-stu   # clone 本 repo
$ mkdocs serve                                      # 本地渲染
INFO     -  Building documentation...
INFO     -  Cleaning site directory
...
INFO     -  [11:00:57] Serving on http://127.0.0.1:8000/syssec-stu/
```

## 致谢

感谢以下各位老师和助教的辛勤付出！

[申文博](https://wenboshen.org/)、周金梦、王星宇、朱若凡、屠锦江、蔡泽超、张有坤、[潘子曰](https://pan-ziyue。github.io)、李程浩、朱家迅、郭若容
