@Library('xmos_jenkins_shared_library@v0.55.0') _

getApproval()

pipeline {
  agent {
    label 'x86_64 && linux'
  }
  options {
    skipDefaultCheckout()
  }
  stages {
    stage('Get view') {
      steps {
        checkout scm
        createVenv(reqFile: 'requirements.txt')
      }
    }
    stage('Python Tests') {
      steps {
        withTools(params.TOOLS_VERSION) {
          withVenv() {
            runPytest()
          }
        }
      }
    }
  }
  post {
    cleanup {
      cleanWs()
    }
  }
}
