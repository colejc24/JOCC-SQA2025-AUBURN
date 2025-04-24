FROM continuumio/miniconda3

WORKDIR /app

RUN conda config --append channels conda-forge

# Create the environment:
COPY environment.yml .
RUN conda env create -v -f environment.yml
RUN pip install ruamel.yaml
RUN pip install pandas sarif_om jschema-to-python typer
RUN apt-get update && apt-get install -y curl jq \
  && curl -L https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -o /usr/bin/yq \
  && chmod +x /usr/bin/yq
# Make RUN commands use the new environment:
RUN echo "conda activate KUBESEC" >> ~/.bashrc
SHELL ["/bin/bash", "--login", "-c"]
ENV PATH /opt/conda/envs/KUBESEC/bin:$PATH

# The code to run when container is started:
COPY constants.py graphtaint.py main.py parser.py scanner.py myLogger.py /app/
COPY TEST_ARTIFACTS/ /home/TEST_ARTIFACTS/
#ENTRYPOINT ["python", "/app/main.py"]
VOLUME ["/results"]

# CMD bash -c "python main.py && exec bash"
CMD bash -c "python main.py && cp /home/slikube_results.csv /results/slikube_results.csv && exec bash"

