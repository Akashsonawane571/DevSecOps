pipeline {
    agent any

    stages {

        stage('Clean Workspace') {
            steps {
                cleanWs()
            }
        }

        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('Prepare Dependencies') {
            agent {
                docker {
                    image 'node:22-alpine'
                    args '--entrypoint="" -u root'
                    reuseNode true
                }
            }
            steps {
                sh """
                    echo "Installing build dependencies..."

                    apk add --no-cache \
                        git \
                        python3 \
                        make \
                        g++

                    if [ -f package.json ]; then
                        echo "Node project detected"
                        npm install
                    else
                        echo "No package.json found"
                    fi
                """
            }
        }

        stage('SBOM Generation (Syft)') {
            steps {
                echo "Generating SBOM..."

                sh """
                    mkdir -p sca/sbom

                    echo "Checking node_modules..."
                    ls -ld node_modules || echo "node_modules not found"

                    docker run --rm \
                      -v \$WORKSPACE:/workspace \
                      anchore/syft:latest /workspace \
                      --catalogers javascript \
                      -o json > sca/sbom/sbom.json

                    echo "SBOM created:"
                    ls -l sca/sbom/
                """
            }
        }

        stage('Vulnerability Scan (Grype)') {
            steps {
                echo "Running Grype scan..."

                sh """
                    mkdir -p sca/reports

                    if [ ! -f sca/sbom/sbom.json ]; then
                        echo "SBOM not found!"
                        exit 1
                    fi

                    docker run --rm \
                      -v \$WORKSPACE:/workspace \
                      anchore/grype:latest sbom:/workspace/sca/sbom/sbom.json \
                      -o json > sca/reports/grype-report.json
                """
            }
        }

        stage('Trivy Scan (CI/CD Gate)') {
            steps {
                echo "Running Trivy scan (CI/CD Gate)..."

                sh """
                    docker run --rm \
                      -v \$WORKSPACE:/workspace \
                      -v trivy-cache:/root/.cache/ \
                      aquasec/trivy:0.49.1 fs /workspace \
                      --scanners vuln \
                      --exit-code 1 \
                      --severity HIGH,CRITICAL
                """
            }
        }

        stage('FOSSA Scan (Policy & License)') {
            steps {
                echo "Running FOSSA scan..."

                withCredentials([string(credentialsId: 'fossa-api-key', variable: 'FOSSA_API_KEY')]) {
                    sh """
                        docker run --rm \
                          -e FOSSA_API_KEY=\$FOSSA_API_KEY \
                          -v \$WORKSPACE:/workspace \
                          -w /workspace \
                          fossa-cli analyze || true
                    """
                }
            }
        }
    }

    post {
        always {
            echo "Archiving reports..."
            archiveArtifacts artifacts: 'sca/**/*.json', fingerprint: true
        }

        success {
            echo "✅ Pipeline passed all security checks!"
        }

        failure {
            echo "❌ Pipeline failed due to HIGH/CRITICAL vulnerabilities!"
        }
    }
}
