'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

interface Contest {
  id: string
  title: string
  description?: string
  type: string
  rules?: string
  rewardType?: string
  rewardValue?: number
  rewardDescription?: string
  startDate: string
  endDate: string
  isActive: boolean
  maxParticipants?: number
  minPointsToJoin?: number
  imageUrl?: string
  terms?: string
  participants?: any[]
  winners?: any[]
  createdAt: string
  updatedAt: string
}

interface Game {
  id: string
  title: string
  description?: string
  type: string
  instructions?: string
  difficulty: string
  estimatedTime?: number
  maxScore: number
  content?: any
  rewards?: any
  pointsPerWin: number
  imageUrl?: string
  videoUrl?: string
  isActive: boolean
  gameSessions?: any[]
  createdAt: string
  updatedAt: string
}

export default function GamesContestsManagement() {
  const [contests, setContests] = useState<Contest[]>([])
  const [games, setGames] = useState<Game[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState('contests')

  // Contest form state
  const [showContestDialog, setShowContestDialog] = useState(false)
  const [editingContest, setEditingContest] = useState<Contest | null>(null)
  const [contestForm, setContestForm] = useState({
    title: '',
    description: '',
    type: 'QUIZ',
    rules: '',
    rewardType: 'POINTS',
    rewardValue: 0,
    rewardDescription: '',
    startDate: '',
    endDate: '',
    isActive: true,
    maxParticipants: '',
    minPointsToJoin: '',
    imageUrl: '',
    terms: ''
  })

  // Game form state
  const [showGameDialog, setShowGameDialog] = useState(false)
  const [editingGame, setEditingGame] = useState<Game | null>(null)
  const [gameForm, setGameForm] = useState({
    title: '',
    description: '',
    type: 'WORD_PUZZLE',
    instructions: '',
    difficulty: 'easy',
    estimatedTime: '',
    maxScore: 100,
    content: '',
    rewards: '',
    pointsPerWin: 10,
    imageUrl: '',
    videoUrl: '',
    isActive: true
  })

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)
      
      // Fetch contests
      const contestsResponse = await fetch('/api/contests')
      if (contestsResponse.ok) {
        const contestsData = await contestsResponse.json()
        if (contestsData.status === 'success') {
          setContests(contestsData.data)
        }
      }

      // Fetch games
      const gamesResponse = await fetch('/api/games')
      if (gamesResponse.ok) {
        const gamesData = await gamesResponse.json()
        if (gamesData.status === 'success') {
          setGames(gamesData.data)
        }
      }

      setError(null)
    } catch (error: any) {
      console.error('Error fetching games and contests:', error)
      setError(error.message)
    } finally {
      setLoading(false)
    }
  }

  // Contest operations
  const saveContest = async () => {
    try {
      const formData = {
        ...contestForm,
        maxParticipants: contestForm.maxParticipants ? parseInt(contestForm.maxParticipants) : null,
        minPointsToJoin: contestForm.minPointsToJoin ? parseInt(contestForm.minPointsToJoin) : null
      }

      const url = editingContest ? `/api/contests/${editingContest.id}` : '/api/contests'
      const method = editingContest ? 'PUT' : 'POST'

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      })

      if (response.ok) {
        await fetchData()
        setShowContestDialog(false)
        resetContestForm()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const deleteContest = async (id: string) => {
    try {
      const response = await fetch(`/api/contests/${id}`, { method: 'DELETE' })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const toggleContestStatus = async (id: string, isActive: boolean) => {
    try {
      const response = await fetch(`/api/contests/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ isActive: !isActive })
      })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  // Game operations
  const saveGame = async () => {
    try {
      const formData = {
        ...gameForm,
        estimatedTime: gameForm.estimatedTime ? parseInt(gameForm.estimatedTime) : null
      }

      const url = editingGame ? `/api/games/${editingGame.id}` : '/api/games'
      const method = editingGame ? 'PUT' : 'POST'

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      })

      if (response.ok) {
        await fetchData()
        setShowGameDialog(false)
        resetGameForm()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const deleteGame = async (id: string) => {
    try {
      const response = await fetch(`/api/games/${id}`, { method: 'DELETE' })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const toggleGameStatus = async (id: string, isActive: boolean) => {
    try {
      const response = await fetch(`/api/games/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ isActive: !isActive })
      })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const resetContestForm = () => {
    setContestForm({
      title: '',
      description: '',
      type: 'QUIZ',
      rules: '',
      rewardType: 'POINTS',
      rewardValue: 0,
      rewardDescription: '',
      startDate: '',
      endDate: '',
      isActive: true,
      maxParticipants: '',
      minPointsToJoin: '',
      imageUrl: '',
      terms: ''
    })
    setEditingContest(null)
  }

  const resetGameForm = () => {
    setGameForm({
      title: '',
      description: '',
      type: 'WORD_PUZZLE',
      instructions: '',
      difficulty: 'easy',
      estimatedTime: '',
      maxScore: 100,
      content: '',
      rewards: '',
      pointsPerWin: 10,
      imageUrl: '',
      videoUrl: '',
      isActive: true
    })
    setEditingGame(null)
  }

  const editContest = (contest: Contest) => {
    setContestForm({
      title: contest.title,
      description: contest.description || '',
      type: contest.type,
      rules: contest.rules || '',
      rewardType: contest.rewardType || 'POINTS',
      rewardValue: contest.rewardValue || 0,
      rewardDescription: contest.rewardDescription || '',
      startDate: contest.startDate.split('T')[0],
      endDate: contest.endDate.split('T')[0],
      isActive: contest.isActive,
      maxParticipants: contest.maxParticipants?.toString() || '',
      minPointsToJoin: contest.minPointsToJoin?.toString() || '',
      imageUrl: contest.imageUrl || '',
      terms: contest.terms || ''
    })
    setEditingContest(contest)
    setShowContestDialog(true)
  }

  const editGame = (game: Game) => {
    setGameForm({
      title: game.title,
      description: game.description || '',
      type: game.type,
      instructions: game.instructions || '',
      difficulty: game.difficulty,
      estimatedTime: game.estimatedTime?.toString() || '',
      maxScore: game.maxScore,
      content: JSON.stringify(game.content || {}),
      rewards: JSON.stringify(game.rewards || {}),
      pointsPerWin: game.pointsPerWin,
      imageUrl: game.imageUrl || '',
      videoUrl: game.videoUrl || '',
      isActive: game.isActive
    })
    setEditingGame(game)
    setShowGameDialog(true)
  }

  if (loading) {
    return <div className="flex items-center justify-center p-8">جاري التحميل...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">إدارة الألعاب والمسابقات</h2>
      </div>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-red-800 font-medium">خطأ: {error}</p>
        </div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="contests">المسابقات</TabsTrigger>
          <TabsTrigger value="games">الألعاب</TabsTrigger>
        </TabsList>

        <TabsContent value="contests" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">إدارة المسابقات</h3>
            <Dialog open={showContestDialog} onOpenChange={setShowContestDialog}>
              <DialogTrigger asChild>
                <Button onClick={resetContestForm}>إضافة مسابقة جديدة</Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>
                    {editingContest ? 'تعديل المسابقة' : 'إنشاء مسابقة جديدة'}
                  </DialogTitle>
                  <DialogDescription>
                    املأ المعلومات التالية لإنشاء مسابقة جديدة
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="title">عنوان المسابقة</Label>
                      <Input
                        id="title"
                        value={contestForm.title}
                        onChange={(e) => setContestForm({ ...contestForm, title: e.target.value })}
                        placeholder="مثال: مسابقة المعرفة الثقافية"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="type">نوع المسابقة</Label>
                      <Select value={contestForm.type} onValueChange={(value) => setContestForm({ ...contestForm, type: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="QUIZ">مسابقة ثقافية</SelectItem>
                          <SelectItem value="TRIVIA">أسئلة معلوماتية</SelectItem>
                          <SelectItem value="PHOTO">مسابقة التصوير</SelectItem>
                          <SelectItem value="REVIEW">مسابقة التقييم</SelectItem>
                          <SelectItem value="LOYALTY">مكافآت الولاء</SelectItem>
                          <SelectItem value="SEASONAL">مسابقة موسمية</SelectItem>
                          <SelectItem value="DAILY">تحدي يومي</SelectItem>
                          <SelectItem value="WEEKLY">تحدي أسبوعي</SelectItem>
                          <SelectItem value="MONTHLY">تحدي شهري</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="description">وصف المسابقة</Label>
                    <Textarea
                      id="description"
                      value={contestForm.description}
                      onChange={(e) => setContestForm({ ...contestForm, description: e.target.value })}
                      placeholder="وصف تفصيلي للمسابقة..."
                      rows={3}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="startDate">تاريخ البداية</Label>
                      <Input
                        id="startDate"
                        type="date"
                        value={contestForm.startDate}
                        onChange={(e) => setContestForm({ ...contestForm, startDate: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="endDate">تاريخ النهاية</Label>
                      <Input
                        id="endDate"
                        type="date"
                        value={contestForm.endDate}
                        onChange={(e) => setContestForm({ ...contestForm, endDate: e.target.value })}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="rewardType">نوع الجائزة</Label>
                      <Select value={contestForm.rewardType} onValueChange={(value) => setContestForm({ ...contestForm, rewardType: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="POINTS">نقاط</SelectItem>
                          <SelectItem value="DISCOUNT">خصم</SelectItem>
                          <SelectItem value="FREE_STAY">إقامة مجانية</SelectItem>
                          <SelectItem value="ROOM_UPGRADE">ترقية غرفة</SelectItem>
                          <SelectItem value="SPA_SERVICE">خدمة سبا</SelectItem>
                          <SelectItem value="RESTAURANT">وجبة مجانية</SelectItem>
                          <SelectItem value="GIFT_CARD">بطاقة هدايا</SelectItem>
                          <SelectItem value="CASH">نقدي</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="rewardValue">قيمة الجائزة</Label>
                      <Input
                        id="rewardValue"
                        type="number"
                        value={contestForm.rewardValue}
                        onChange={(e) => setContestForm({ ...contestForm, rewardValue: parseFloat(e.target.value) })}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="maxParticipants">الحد الأقصى للمشاركين</Label>
                      <Input
                        id="maxParticipants"
                        type="number"
                        value={contestForm.maxParticipants}
                        onChange={(e) => setContestForm({ ...contestForm, maxParticipants: e.target.value })}
                        placeholder="اتركه فارغاً للحد غير المحدود"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="minPointsToJoin">الحد الأدنى للنقاط للانضمام</Label>
                      <Input
                        id="minPointsToJoin"
                        type="number"
                        value={contestForm.minPointsToJoin}
                        onChange={(e) => setContestForm({ ...contestForm, minPointsToJoin: e.target.value })}
                        placeholder="اتركه فارغاً لعدم وجود حد أدنى"
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="rules">قواعد المسابقة</Label>
                    <Textarea
                      id="rules"
                      value={contestForm.rules}
                      onChange={(e) => setContestForm({ ...contestForm, rules: e.target.value })}
                      placeholder="قواعد المسابقة..."
                      rows={3}
                    />
                  </div>
                  <div className="flex items-center space-x-2">
                    <Switch
                      id="isActive"
                      checked={contestForm.isActive}
                      onCheckedChange={(checked) => setContestForm({ ...contestForm, isActive: checked })}
                    />
                    <Label htmlFor="isActive">مسابقة نشطة</Label>
                  </div>
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowContestDialog(false)}>
                    إلغاء
                  </Button>
                  <Button onClick={saveContest}>
                    {editingContest ? 'تحديث' : 'إنشاء'}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>قائمة المسابقات</CardTitle>
              <CardDescription>إدارة جميع المسابقات والحملات</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>العنوان</TableHead>
                    <TableHead>النوع</TableHead>
                    <TableHead>تاريخ البداية</TableHead>
                    <TableHead>تاريخ النهاية</TableHead>
                    <TableHead>المشاركون</TableHead>
                    <TableHead>الحالة</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {contests.map((contest) => (
                    <TableRow key={contest.id}>
                      <TableCell className="font-medium">{contest.title}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{contest.type}</Badge>
                      </TableCell>
                      <TableCell>{new Date(contest.startDate).toLocaleDateString('ar')}</TableCell>
                      <TableCell>{new Date(contest.endDate).toLocaleDateString('ar')}</TableCell>
                      <TableCell>
                        {contest.participants?.length || 0}
                        {contest.maxParticipants && ` / ${contest.maxParticipants}`}
                      </TableCell>
                      <TableCell>
                        <Badge variant={contest.isActive ? "default" : "secondary"}>
                          {contest.isActive ? 'نشط' : 'غير نشط'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => editContest(contest)}
                          >
                            تعديل
                          </Button>
                          <Button
                            size="sm"
                            variant={contest.isActive ? "destructive" : "default"}
                            onClick={() => toggleContestStatus(contest.id, contest.isActive)}
                          >
                            {contest.isActive ? 'إيقاف' : 'تفعيل'}
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => deleteContest(contest.id)}
                          >
                            حذف
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="games" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">إدارة الألعاب</h3>
            <Dialog open={showGameDialog} onOpenChange={setShowGameDialog}>
              <DialogTrigger asChild>
                <Button onClick={resetGameForm}>إضافة لعبة جديدة</Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>
                    {editingGame ? 'تعديل اللعبة' : 'إنشاء لعبة جديدة'}
                  </DialogTitle>
                  <DialogDescription>
                    املأ المعلومات التالية لإنشاء لعبة جديدة
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="gameTitle">عنوان اللعبة</Label>
                      <Input
                        id="gameTitle"
                        value={gameForm.title}
                        onChange={(e) => setGameForm({ ...gameForm, title: e.target.value })}
                        placeholder="مثال: لعبة الكلمات المتقاطعة"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="gameType">نوع اللعبة</Label>
                      <Select value={gameForm.type} onValueChange={(value) => setGameForm({ ...gameForm, type: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="WORD_PUZZLE">ألعاب الكلمات</SelectItem>
                          <SelectItem value="MEMORY">ألعاب الذاكرة</SelectItem>
                          <SelectItem value="MATCHING">ألعاب المطابقة</SelectItem>
                          <SelectItem value="QUIZ">ألعاب الاختبار</SelectItem>
                          <SelectItem value="WORD_SEARCH">البحث عن الكلمات</SelectItem>
                          <SelectItem value="CROSSWORD">الكلمات المتقاطعة</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="gameDescription">وصف اللعبة</Label>
                    <Textarea
                      id="gameDescription"
                      value={gameForm.description}
                      onChange={(e) => setGameForm({ ...gameForm, description: e.target.value })}
                      placeholder="وصف تفصيلي للعبة..."
                      rows={3}
                    />
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="difficulty">مستوى الصعوبة</Label>
                      <Select value={gameForm.difficulty} onValueChange={(value) => setGameForm({ ...gameForm, difficulty: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="easy">سهل</SelectItem>
                          <SelectItem value="medium">متوسط</SelectItem>
                          <SelectItem value="hard">صعب</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="estimatedTime">الوقت المتوقع (دقيقة)</Label>
                      <Input
                        id="estimatedTime"
                        type="number"
                        value={gameForm.estimatedTime}
                        onChange={(e) => setGameForm({ ...gameForm, estimatedTime: e.target.value })}
                        placeholder="5"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="maxScore">الدرجة القصوى</Label>
                      <Input
                        id="maxScore"
                        type="number"
                        value={gameForm.maxScore}
                        onChange={(e) => setGameForm({ ...gameForm, maxScore: parseInt(e.target.value) })}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="instructions">تعليمات اللعبة</Label>
                    <Textarea
                      id="instructions"
                      value={gameForm.instructions}
                      onChange={(e) => setGameForm({ ...gameForm, instructions: e.target.value })}
                      placeholder="كيفية لعب اللعبة..."
                      rows={3}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="pointsPerWin">النقاط للفوز</Label>
                      <Input
                        id="pointsPerWin"
                        type="number"
                        value={gameForm.pointsPerWin}
                        onChange={(e) => setGameForm({ ...gameForm, pointsPerWin: parseInt(e.target.value) })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="imageUrl">رابط الصورة</Label>
                      <Input
                        id="imageUrl"
                        value={gameForm.imageUrl}
                        onChange={(e) => setGameForm({ ...gameForm, imageUrl: e.target.value })}
                        placeholder="https://example.com/image.jpg"
                      />
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Switch
                      id="gameIsActive"
                      checked={gameForm.isActive}
                      onCheckedChange={(checked) => setGameForm({ ...gameForm, isActive: checked })}
                    />
                    <Label htmlFor="gameIsActive">لعبة نشطة</Label>
                  </div>
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowGameDialog(false)}>
                    إلغاء
                  </Button>
                  <Button onClick={saveGame}>
                    {editingGame ? 'تحديث' : 'إنشاء'}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>قائمة الألعاب</CardTitle>
              <CardDescription>إدارة جميع الألعاب التفاعلية</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>العنوان</TableHead>
                    <TableHead>النوع</TableHead>
                    <TableHead>الصعوبة</TableHead>
                    <TableHead>الوقت المتوقع</TableHead>
                    <TableHead>الجلسات</TableHead>
                    <TableHead>الحالة</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {games.map((game) => (
                    <TableRow key={game.id}>
                      <TableCell className="font-medium">{game.title}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{game.type}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={game.difficulty === 'easy' ? 'default' : game.difficulty === 'medium' ? 'secondary' : 'destructive'}>
                          {game.difficulty === 'easy' ? 'سهل' : game.difficulty === 'medium' ? 'متوسط' : 'صعب'}
                        </Badge>
                      </TableCell>
                      <TableCell>{game.estimatedTime || '-'} دقيقة</TableCell>
                      <TableCell>{game.gameSessions?.length || 0}</TableCell>
                      <TableCell>
                        <Badge variant={game.isActive ? "default" : "secondary"}>
                          {game.isActive ? 'نشط' : 'غير نشط'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => editGame(game)}
                          >
                            تعديل
                          </Button>
                          <Button
                            size="sm"
                            variant={game.isActive ? "destructive" : "default"}
                            onClick={() => toggleGameStatus(game.id, game.isActive)}
                          >
                            {game.isActive ? 'إيقاف' : 'تفعيل'}
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => deleteGame(game.id)}
                          >
                            حذف
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}