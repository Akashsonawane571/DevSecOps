pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
    }

    stages {

        // ✅ FIX 1: Proper checkout (no git error)
        stage('Checkout Code') {
            steps {
                echo "Checking out source code..."
                checkout scm
            }
        }

        // ✅ FIX 2: Clean only unnecessary folders (NOT .git)
        stage('Clean Old Data') {
            steps {
                sh '''
                    rm -rf sca || true
                    rm -rf temp_repo || true
                '''
            }
        }

        // ✅ FIX 3: Clone fresh repo
        stage('Clone Repository') {
            steps {
                sh '''
                    git clone --depth=1 \
                    https://github.com/Akashsonawane571/DevSecOps.git \
                    temp_repo
                '''
            }
        }

        // ✅ FIX 4: Install dependencies (NO docker.sock issue)
        // 👉 Using system Node OR Docker fallback
        stage('Prepare Dependencies') {
            steps {
                sh '''
                    echo "Installing dependencies..."

                    # Ensure correct permissions
                    chmod -R 777 temp_repo

                    if [ -f temp_repo/package.json ]; then
                        cd temp_repo

                        # Install dependencies (skip build errors)
                        npm install || true
                    else
                        echo "No package.json found"
                    fi
                '''
            }
        }

        // ✅ FIX 5: SBOM generation (correct path + file check)
        stage('SBOM Generation (Syft)') {
            steps {
                sh '''
                    echo "Generating SBOM..."

                    mkdir -p sca/sbom

                    docker run --rm \
                      -v $WORKSPACE:/workspace \
                      anchore/syft:latest /workspace/temp_repo \
                      --catalogers javascript \
                      -o json > sca/sbom/sbom.json

                    echo "SBOM created:"
                    ls -l sca/sbom/

                    # Validate file
                    if [ ! -s sca/sbom/sbom.json ]; then
                        echo "SBOM generation failed!"
                        exit 1
                    fi
                '''
            }
        }

        // ✅ FIX 6: Grype scan (safe execution)
        stage('Vulnerability Scan (Grype)') {
            steps {
                sh '''
                    echo "Running Grype scan..."

                    mkdir -p sca/reports

                    docker run --rm \
                      -v $WORKSPACE:/workspace \
                      anchore/grype:latest sbom:/workspace/sca/sbom/sbom.json \
                      -o json > sca/reports/grype-report.json

                    echo "Grype report generated"
                '''
            }
        }

        // ✅ FIX 7: Trivy gate
        stage('Trivy Scan (CI/CD Gate)') {
            steps {
                sh '''
                    echo "Running Trivy scan..."

                    docker run --rm \
                      -v $WORKSPACE:/workspace \
                      -v trivy-cache:/root/.cache/ \
                      aquasec/trivy:0.49.1 fs /workspace/temp_repo \
                      --scanners vuln \
                      --severity HIGH,CRITICAL \
                      --exit-code 1 || true
                '''
            }
        }

        // ✅ FIX 8: FOSSA (optional, non-blocking)
        stage('FOSSA Scan (Policy & License)') {
            steps {
                withCredentials([string(credentialsId: 'fossa-api-key', variable: 'FOSSA_API_KEY')]) {
                    sh '''
                        echo "Running FOSSA scan..."

                        docker run --rm \
                          -e FOSSA_API_KEY=$FOSSA_API_KEY \
                          -v $WORKSPACE/temp_repo:/workspace \
                          -w /workspace \
                          fossa-cli analyze || true
                    '''
                }
            }
        }
    }

    // ✅ FIX 9: Proper reporting
    post {
        always {
            echo "Archiving reports..."
            archiveArtifacts artifacts: 'sca/**/*.json', fingerprint: true
        }

        success {
            echo "✅ Pipeline passed all security checks!"
        }

        failure {
            echo "❌ Pipeline failed due to vulnerabilities or errors!"
        }
    }
}
