FROM python:3.12-slim
WORKDIR /app
RUN useradd --uid 10001 --create-home crm && mkdir /app/data && chown crm:crm /app/data
COPY --chown=crm:crm server.py /app/server.py
COPY --chown=crm:crm public /app/public
USER crm
ENV HOST=0.0.0.0 PORT=8000 CRM_DB=/app/data/crm.sqlite3
EXPOSE 8000
CMD ["python", "server.py"]
