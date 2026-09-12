# panelbeater — network (Wi-Fi) transport, with PDF + blank-page removal.
# Built for linux/amd64. Pure-Python app; the extras (img2pdf, Pillow, numpy)
# all ship manylinux wheels, so nothing is compiled.
FROM python:3.12-slim

# The "pdf" extra pulls img2pdf; "blank" pulls Pillow + numpy. No USB extra:
# this image is for the network transport only.
COPY pyproject.toml README.md /src/
COPY panelbeater /src/panelbeater
RUN pip install --no-cache-dir "/src[pdf,blank]" \
    && rm -rf /src

# Run unprivileged. The daemon only needs to open TCP to the scanner and bind
# UDP 53220/55265 (both > 1024), which needs no extra capability.
RUN useradd --create-home --uid 1000 scan
USER scan
WORKDIR /home/scan

# This image has no pyusb, so force the network transport. Otherwise `auto`
# imports the USB module on startup and crashes with ModuleNotFoundError.
ENV PANELBEATER_TRANSPORT=network

# Where finished scans land. Override with PANELBEATER_OUTPUT_DIR / a bind mount.
ENV PANELBEATER_OUTPUT_DIR=/scans
VOLUME ["/scans"]

# -u: unbuffered, so the container log shows scan progress live.
ENTRYPOINT ["python", "-u", "-m", "panelbeater"]
CMD ["serve"]
