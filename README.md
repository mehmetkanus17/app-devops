# CI/CD 
Bu doküman, CI/CD (Sürekli Entegrasyon/Sürekli Dağıtım) sürecini detaylandırmaktadır. Proje, `.NET Core` ile geliştirilmiş örnek bir uygulama üzerinden **GitHub Actions** kullanılarak CI pipeline'ının oluşturulmasını ve **ArgoCD** gibi bir GitOps aracı ile CD süreçlerinin otomasyonunu kapsamaktadır. Temel felsefe **"her şeyi kod olarak yapmak"**, **"doğru iş için doğru aracı kullanmak"** ve **"modüler, genişleyebilir yapılar oluşturmak"** üzerine kurulmuştur.

## CI/CD Süreci
Bu bölümde, projenin CI/CD aşamaları derinlemesine incelenecek ve kullanılan araçlar ile iş akışları adım adım açıklanacaktır.

a. Uygulama Seçimi
Proje için ilişkisel veritabanı **(Postgresql)** kullanan, veri kalıcılığı sağlayan (stateful) ve basit bir arayüze sahip bir `.NET Core` uygulaması kullanılmıştır.

b. Kod Deposunun Yapısı
Uygulamanın kaynak kodu, app-[aday_ismi] (örneğin, app-mehmetkanus) adında ayrı bir Git deposunda bulunmaktadır. Bu yapı, uygulama kodunun versiyon kontrolü ve yönetimi için merkezi bir nokta sağlar.

c. CD Süreçlerinin Tetiklenmesi
Bu projenin önemli bir özelliği, CD işlemlerinin CI aracı tarafından doğrudan yapılmamasıdır. Bunun yerine, CI aracı (GitHub Actions), ArgoCD gibi bir CD aracını tetikleyerek dağıtımların otomatik olarak gerçekleşmesini sağlar. Bu yaklaşım, GitOps prensiplerine uygun olarak, Kubernetes kümesinin durumunun Git deposu üzerinden yönetilmesini ve dış müdahalelerle değil, yalnızca Git'teki değişikliklerle güncellenmesini sağlar. GitHub Actions, Kubernetes manifestlerinin bulunduğu GitOps deposuna gerekli push işlemlerini yaparak ArgoCD'nin devreye girmesini ve değişiklikleri algılamasını sağlar.

d. Ortam Yapısı
Tek bir Kubernetes kümesi içerisinde iki farklı ortam bulunmaktadır: dev (geliştirme) ve prod (üretim). Bu ortamlar, namespace seviyesinde birbirinden ayrılmıştır. Bu ayrım, geliştirme ve üretim ortamları arasında izolasyon sağlayarak olası hataların üretim ortamını etkilemesini engeller.

e. Kubernetes Manifestleri ve Ortam Farklılıkları
dev ve prod ortamlarına ait Kubernetes manifestleri, manifest-[aday_ismi] (örneğin, manifest-mehmetkanus) adında tek bir Git deposunda ve tek bir ana dalda (master/main) tutulmaktadır. Ortama özel değişen konfigürasyonlar ise Kustomization.yaml dosyaları ile yönetilmektedir. Bu sayede, manifestler tekrarlanmadan, ortamlar arası farklılıklar şeffaf bir şekilde yönetilebilir ve "her şeyi kod olarak yap" felsefesi pekiştirilir.

f. CI Pipeline'ı (GitHub Actions)
Uygulamanın CI pipeline'ı GitHub Actions kullanılarak oluşturulmuştur. Bu pipeline, uygulamanın sürekli entegrasyon sürecini otomatize eder ve aşağıdaki minimum adımları içerir:

GitHub Actions Workflow Dosyası İncelemesi

Aşağıda, belirtilen CI/CD gereksinimlerini karşılamak üzere tasarlanmış GitHub Actions workflow dosyası adım adım açıklanmaktadır.

````yaml
name: CI/CD Pipeline for Application
# 1.ADIM: pipeline'nın tetiklenmesi
on:
  push:
    branches:
      - main
      - feature
  pull_request:
    branches:
      - main
      - feature
  workflow_dispatch:
    inputs:
      run-options:
        description: 'Select run-options. (mandatory)'
        required: true
        default: 'only-build-job'
        type: choice
        options:
        - only-build-job
        - run-all
env:
  APP_NAME: simple-todo-app
  HARBOR_URL: harbor.prod.goxdev.lol
  APP_IMAGE: harbor.prod.goxdev.lol/app-mehmetkanus/todoapp
  GITOPS_REPO: ${{ github.repository_owner }}/manifest-mehmetkanus
  DOCKERFILE_PATH: ./SimpleTodoApp/Dockerfile
  APP_SOURCE_DIR: ./SimpleTodoApp
  DEV_APP_URL: app.dev.goxdev.lol
  PROD_APP_URL: app.prod.goxdev.lol
````
1. Pipeline'ın Tetiklenmesi (on):
Pipeline, aşağıdaki olaylarla tetiklenir:

push: main veya feature dallarına yapılan push işlemleri.

pull_request: main veya feature dallarına açılan pull request'ler.

workflow_dispatch: Manuel olarak tetiklenebilen bir seçenektir. run-options girişi ile sadece build adımını çalıştırma (only-build-job) veya tüm pipeline'ı çalıştırma (run-all) seçeneği sunar. Bu, özellikle geliştirme ve test süreçlerinde esneklik sağlar.

Ortam Değişkenleri (env):
Pipeline genelinde kullanılan çeşitli ortam değişkenleri tanımlanmıştır. Bu değişkenler, uygulama adı, Harbor URL'si, Docker imaj adı, GitOps deposu URL'si gibi bilgileri içerir ve kodun daha okunabilir ve yönetilebilir olmasını sağlar.

````yaml
jobs:
  build-and-test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      pull-requests: write # DAST yorumları için gerekebilir
    steps:
      - name: Checkout Source Code
        uses: actions/checkout@v4

# 2. ADIM: source kodların static kod analizi (SAST) ile taranması
      - name: Trivy Filesystem Scan (SAST)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'
          ignore-unfixed: true
          format: table
````
(1) Kod Değişikliklerinin Tetiklenmesi ve (2) Statik Kod Analizi (SAST):

Adım (1) - Kod Değişikliklerinin Tetiklenmesi: Geliştirici, kodu bir feature dalında değiştirir ve bu değişiklikleri uzak feature dalına pushladığında pipeline tetiklenir. pull_request veya main dalına push durumları da pipeline'ı otomatik olarak başlatır.

Adım (2) - Statik Kod Analizi (SAST): Trivy Filesystem Scan (SAST) adımı ile yeni kod değişiklikleri statik bir kod analiz aracı olan Trivy ile taranır. Bu tarama, kod tabanındaki potansiyel güvenlik açıklarını, hataları ve kötü kodlama alışkanlıklarını tespit etmeye yardımcı olur. CRITICAL ve HIGH seviyesindeki güvenlik zafiyetleri için pipeline'ın başarısız olması (exit-code: '1') sağlanarak kalitenin düşürülmesi engellenir.

````yaml
# 4. ADIM: image'in build edilip Harbor'a pushlanması
    # a. image registry'e login 
      - name: Login to Harbor
        uses: docker/login-action@v3
        with:
          registry: ${{ env.HARBOR_URL }}
          username: ${{ secrets.HARBOR_USERNAME }}
          password: ${{ secrets.HARBOR_PASSWORD }}

    # b. image tag'lerinin belirlenmesi
      - name: Extract metadata (tags, labels) for Docker
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.APP_IMAGE }}
          tags: |
            ${{ github.sha }}
            latest
    # c. image'in build edilmesi ve push'lanması
      - name: Build and Push Docker Image to Harbor
        id: push
        uses: docker/build-push-action@v6
        with:
          context: ${{ env.APP_SOURCE_DIR }}
          file: ${{ env.DOCKERFILE_PATH }}
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
    # d. oluşturulan image'in güvenlik analizi
      - name: Trivy Image Scan (SAST - Image)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: '${{ env.APP_IMAGE }}:${{ github.sha }}'
          exit-code: '0'
          severity: 'CRITICAL,HIGH'
          ignore-unfixed: true
          format: 'table'
````
(3) Kodun Derlenmesi ve (4) Konteyner İmajının Oluşturulması ve Harbor'a Pushlanması:

Adım (3) - Kodun Derlenmesi: GitHub Actions workflow'unda açıkça bir ".NET Core derleme" adımı görünmemektedir, ancak docker/build-push-action kullanılırken Dockerfile içindeki .NET SDK komutları (örneğin, dotnet publish) sayesinde kod derlenmiş ve çıktıları konteyner imajına dahil edilmiştir. Bu, "doğru iş için doğru aracı kullan" felsefesine uygun olarak Docker'ın kendi build mekanizması içinde derleme işlemini gerçekleştirmesi anlamına gelir.

Adım (4) - Konteyner İmajının Oluşturulması ve Harbor'a Pushlanması:

Harbor'a Giriş (Login to Harbor): İlk olarak, uygulamanın konteyner imajını depolayacak olan Harbor Image Registry'ye kimlik doğrulama işlemi yapılır. Güvenlik için kimlik bilgileri GitHub Secrets (secrets.HARBOR_USERNAME, secrets.HARBOR_PASSWORD) kullanılarak yönetilir.

İmaj Etiketlerinin Belirlenmesi (Extract metadata for Docker): github.sha (commit hash) ve latest etiketleri kullanılarak imaj için meta veriler oluşturulur. github.sha'nın kullanılması, her imajın belirli bir kod değişikliği ile eşleşmesini sağlayarak izlenebilirliği artırır.

İmajın Oluşturulması ve Push'lanması (Build and Push Docker Image to Harbor): docker/build-push-action kullanılarak uygulama kodu Dockerfile üzerinden bir konteyner imajına dönüştürülür ve Harbor'a push edilir.

Oluşturulan İmajın Güvenlik Analizi (Trivy Image Scan (SAST - Image)): Trivy kullanılarak yeni oluşturulan Docker imajı güvenlik zafiyetlerine karşı taranır. Bu, imajın içerdiği kütüphanelerde ve bağımlılıklarda bilinen güvenlik açıklarının tespit edilmesine yardımcı olur.

````yaml
  deploy-to-dev:
    needs: build-and-test
    if: github.event_name != 'workflow_dispatch' || inputs.run-options == 'run-all'

    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - name: Update GitOps deployment repo
        run: |
          git clone https://${{ secrets.GITOPS_PAT }}@github.com/${{ env.GITOPS_REPO }} gitops
          cd gitops

          # Güncel image tag'i
          export APP_IMAGE="${{ env.APP_IMAGE }}"
          export TAG="${{ github.sha }}"

          sed -i "s|newTag: .*|newTag: ${TAG}|g" ./overlays/dev/kustomization.yaml

          git config user.name "GitHub Actions"
          git config user.email "actions@github.com"
          git add ./overlays/dev/kustomization.yaml
          git commit -m "Update image:${{ env.APP_IMAGE }} tag to ${TAG}"
          git push origin main
````
(5) Dev Ortamına Dağıtımın Tetiklenmesi:

deploy-to-dev Job'u: Bu adım, build-and-test job'ı başarıyla tamamlandıktan sonra çalışır. workflow_dispatch tetiklemesi durumunda eğer run-options run-all seçilmediyse bu adım atlanır.

GitOps Deposu Güncelleme (Update GitOps deployment repo): CI aracı (GitHub Actions), Kubernetes manifestlerinin bulunduğu GitOps deposuna (manifest-mehmetkanus) erişir. Burada dev ortamına ait kustomization.yaml dosyası içinde uygulamanın yeni imaj etiketi (github.sha) güncellenir. Bu değişiklik, Git deposuna commit edilir ve main dalına pushlanır.

ArgoCD Tetiklenmesi: GitOps deposundaki bu değişiklik, otomatik olarak ArgoCD tarafından algılanır. ArgoCD, kustomization.yaml dosyasındaki yeni imaj etiketini görür ve buna göre dev ortamındaki uygulamanın dağıtımını otomatik olarak günceller. Bu sayede, CI aracı doğrudan Kubernetes kümesine erişmek yerine, GitOps deposu üzerinden CD sürecini tetiklemiş olur.

````yaml
# 6.ADIM: Dinamik Güvenlik Analizi (DAST) #
  dynamic-analysis-DAST:
    needs: deploy-to-dev
    if: github.event_name != 'workflow_dispatch' || inputs.run-options == 'run-all'
    runs-on: ubuntu-latest
    steps:
      - name: Uygulamanın hazır olmasını bekle.
        run: |
          echo "app.dev.mehmetkanus.com sitesinin hazır olmasını bekleyin."
          sleep 30

      - name: ZAP Baseline Scan (DAST)
        uses: zaproxy/action-baseline@v0.14.0
        with:
          token: ${{ secrets.GITOPS_PAT }}
          docker_name: 'ghcr.io/zaproxy/zaproxy:stable'
          target: 'https://${{ env.DEV_APP_URL }}'
          cmd_options: '-a'
````

(6) Dinamik Güvenlik Analizi (DAST):

dynamic-analysis-DAST Job'u: deploy-to-dev job'ı tamamlandıktan sonra bu adım devreye girer.

Uygulamanın Hazır Olmasını Bekleme: DAST taramasından önce, dev ortamına dağıtılan uygulamanın tamamen başlatılmasını ve erişilebilir olmasını sağlamak için kısa bir bekleme süresi (sleep 30) eklenmiştir.

ZAP Baseline Scan (DAST): Uygulama dev ortamında çalışmaya başladıktan sonra, OWASP ZAP (Zed Attack Proxy) kullanılarak dinamik güvenlik analizi (DAST) yapılır. ZAP, çalışan uygulamayı tarayarak potansiyel güvenlik açıklarını (örneğin, SQL Injection, XSS) gerçek zamanlı olarak tespit etmeye çalışır. Bu adım, uygulamanın çalıştığı ortamdaki güvenlik zafiyetlerini bulmak için önemlidir.

````yaml
# 7.ADIM: Manuel Onay Adımı
  manual-approval-for-prod:
    needs: dynamic-analysis-DAST
    if: github.event_name != 'workflow_dispatch' || inputs.run-options == 'run-all'
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - name: Manual approval to deploy to production
        uses: trstringer/manual-approval@v1
        with:
          secret: ${{ secrets.GITOPS_PAT }}
          approvers: mehmetkanus17
          minimum-approvals: 1
          issue-title: "Deployment Approval for Production - ${{ github.sha }}"
          issue-body: |
            Uygulama ${{ github.sha }} versiyonu üretim ortamına dağıtılmak üzere hazır.
            Lütfen inceleyin ve onaylamak için 'approve' veya reddetmek için 'deny' yazın.
            DAST Raporları: [ZAP Raporları](https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }})
````

(7) Prod Ortamına Dağıtım Öncesi Manuel Onay Adımı:

manual-approval-for-prod Job'u: dynamic-analysis-DAST job'ı tamamlandıktan sonra, üretim ortamına dağıtım yapılmadan önce manuel bir onay adımı eklenir.

trstringer/manual-approval@v1: Bu eylem, belirli kişilerin (burada mehmetkanus17) dağıtımı onaylamasını veya reddetmesini gerektiren bir GitHub Issue oluşturur. Bu, kritik üretim ortamlarına yapılan dağıtımların kontrol altında tutulmasını ve istenmeyen değişikliklerin önüne geçilmesini sağlar. Onay mekanizması, güvenlik ve uyumluluk açısından önemli bir kontrol noktasıdır. Issue body kısmına DAST raporlarına yönlendiren bir link eklenerek ilgili raporların kolayca incelenmesi sağlanmıştır.

````yaml
# 8.ADIM: prod konfigürasyonu ile prod ortamına deploy edilmesi
  deploy-to-prod:
    needs: manual-approval-for-prod
    if: github.event_name != 'workflow_dispatch' || inputs.run-options == 'run-all'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - name: Update GitOps deployment repo
        run: |
          git clone https://${{ secrets.GITOPS_PAT }}@github.com/${{ env.GITOPS_REPO }} gitops
          cd gitops

          # Güncel image tag'i
          export APP_IMAGE="${{ env.APP_IMAGE }}"
          export TAG="${{ github.sha }}"

          sed -i "s|newTag: .*|newTag: ${TAG}|g" ./overlays/prod/kustomization.yaml

          git config user.name "GitHub Actions"
          git config user.email "actions@github.com"
          git add ./overlays/prod/kustomization.yaml
          git commit -m "Update image:${{ env.APP_IMAGE }} tag to ${TAG}"
          git push origin main
````

(8) Prod Ortamına Dağıtımın Tetiklenmesi:

deploy-to-prod Job'u: Manuel onay adımı başarıyla geçildikten sonra bu adım çalışır.

GitOps Deposu Güncelleme (Update GitOps deployment repo): deploy-to-dev adımına benzer şekilde, bu kez prod ortamına ait kustomization.yaml dosyası içindeki uygulamanın imaj etiketi güncellenir. Bu değişiklik GitOps deposuna commit edilerek main dalına pushlanır.

ArgoCD Tetiklenmesi: GitOps deposundaki bu değişiklik, ArgoCD tarafından algılanır ve üretim ortamındaki uygulamanın dağıtımını otomatik olarak günceller. Bu, manuel müdahale olmadan güvenli ve otomatik bir üretim dağıtımı sağlar.

(9) Geliştirme Dalının Master/Main Dalına Birleştirilmesi:
Bu adım, GitHub Actions workflow dosyasında açıkça bir merge işlemi olarak yer almamaktadır. Ancak, gerçek bir CI/CD sürecinde, üretim ortamına dağıtım başarılı olduktan sonra veya manuel onay sonrası, geliştirmenin yapıldığı feature dalının main dalına birleştirilmesi beklenir. Bu birleştirme genellikle bir Pull Request (PR) aracılığıyla yapılır ve PR'ın kabul edilmesiyle main dalı güncel hale gelir. Bu adım, kod tabanının her zaman güncel kalmasını ve main dalının her zaman dağıtıma hazır bir durumu temsil etmesini sağlar.

Sonuç
Bu CI/CD pipeline'ı, .NET Core uygulamasının geliştirilmesinden üretime dağıtımına kadar olan tüm süreci otomatize etmektedir. GitHub Actions ile entegrasyon, güvenlik analizleri (SAST, DAST), GitOps prensipleriyle ArgoCD üzerinden dağıtım ve manuel onay adımları gibi modern DevOps uygulamalarını bir araya getirerek güvenli, hızlı ve tutarlı bir yazılım teslim süreci sunmaktadır. "Her şeyi kod olarak yap" ve "doğru iş için doğru aracı kullan" felsefeleri, pipeline'ın tasarımında ve uygulamasında temel prensipler olarak benimsenmiştir.