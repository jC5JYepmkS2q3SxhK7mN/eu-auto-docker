FROM python:3.11-slim-bookworm

WORKDIR /app

# 安装必要的系统依赖（ddddocr 核心所需的图形和系统基础库）
RUN apt-get update && apt-get install -y --no-install-recommends \
    cron \
    dos2unix \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件并安装 Python 库
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目文件
COPY euser_renew.py .
COPY entrypoint.sh .

# 解决 Windows 换行符问题并设置执行权限
RUN dos2unix /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# 设置时区为中国上海
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 入口脚本
ENTRYPOINT ["/app/entrypoint.sh"]
