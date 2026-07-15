FROM python:3.12-alpine

RUN pip install --no-cache-dir \
	flask==3.0.3 \
	ldap3==2.9.1 \
	waitress==3.0.2

COPY app /app
WORKDIR /app

EXPOSE 8080
CMD ["python", "app.py"]
